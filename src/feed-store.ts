import type { Pool } from 'pg';
import { z } from 'zod';
import { parseKev, parseEpss, FeedError } from './feeds.js';
import { StaleReview } from './store.js';

export async function initializeFeeds(pool: Pool): Promise<void> {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS eq_feed_snapshots (
      id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
      source text NOT NULL CHECK(source IN ('cisa-kev','first-epss')),
      hash text NOT NULL CHECK(hash ~ '^[a-f0-9]{64}$'),
      published_on date NOT NULL,
      version text NOT NULL,
      row_count integer NOT NULL CHECK(row_count BETWEEN 1 AND 1000000),
      provenance jsonb NOT NULL CHECK(jsonb_typeof(provenance)='object'),
      created_at timestamptz NOT NULL DEFAULT now(),
      UNIQUE(source,id)
    );
    CREATE TABLE IF NOT EXISTS eq_feed_rows (
      snapshot_id bigint NOT NULL REFERENCES eq_feed_snapshots(id),
      cve text COLLATE "C" NOT NULL CHECK(cve ~ '^CVE-[0-9]{4}-[0-9]{4,19}$'),
      evidence jsonb NOT NULL CHECK(jsonb_typeof(evidence)='object'),
      PRIMARY KEY(snapshot_id,cve)
    );
    CREATE TABLE IF NOT EXISTS eq_feed_active (
      source text PRIMARY KEY,
      snapshot_id bigint NOT NULL,
      FOREIGN KEY(source,snapshot_id) REFERENCES eq_feed_snapshots(source,id)
    );
  `);
}

/** Input is original decoded bytes, never caller-normalized feed rows. */
export async function activateFeed(
  pool: Pool,
  source: 'cisa-kev' | 'first-epss',
  bytes: Uint8Array,
  asOf: string,
  expectedHash: string,
  expectedRevision: number,
  provenance: { url: string; retrievedAt: string; archiveSha256: string },
) {
  if (!Number.isSafeInteger(expectedRevision) || expectedRevision < 0)
    throw new FeedError('Invalid workspace revision');
  if (source !== 'cisa-kev' && source !== 'first-epss')
    throw new FeedError('Unknown feed source');
  const acquisition = z
    .strictObject({
      url: z
        .url()
        .max(2048)
        .refine((value) => {
          const u = new URL(value);
          return u.protocol === 'https:' && !u.username && !u.password;
        }),
      retrievedAt: z.iso.datetime(),
      archiveSha256: z.string().regex(/^[a-f0-9]{64}$/),
    })
    .safeParse(provenance);
  if (!acquisition.success)
    throw new FeedError('Invalid acquisition provenance');
  const snapshot =
    source === 'cisa-kev' ? parseKev(bytes, asOf) : parseEpss(bytes, asOf);
  if (snapshot.sha256 !== expectedHash)
    throw new FeedError('Feed bytes changed');
  const client = await pool.connect();
  let broken = false;
  try {
    await client.query('BEGIN');
    await client.query("SET LOCAL lock_timeout = '5s'");
    const state = await client.query<{ revision: number }>(
      'SELECT revision FROM eq_workspace WHERE id=1 FOR UPDATE',
    );
    if (state.rows[0]?.revision !== expectedRevision)
      throw new StaleReview('Workspace changed; review again');
    const previous = await client.query<{ hash: string; day: string }>(
      'SELECT s.hash, s.published_on::text AS day FROM eq_feed_active a JOIN eq_feed_snapshots s ON s.id=a.snapshot_id WHERE a.source=$1',
      [source],
    );
    const prior = previous.rows[0];
    if (
      prior &&
      (snapshot.publishedOn < prior.day ||
        (snapshot.publishedOn === prior.day && snapshot.sha256 !== prior.hash))
    )
      throw new FeedError('Older or conflicting same-day feed refused');
    const inserted = await client.query<{ id: string }>(
      `INSERT INTO eq_feed_snapshots(source,hash,published_on,version,row_count,provenance) VALUES($1,$2,$3,$4,$5,$6) RETURNING id`,
      [
        source,
        snapshot.sha256,
        snapshot.publishedOn,
        snapshot.version,
        snapshot.rows.length,
        JSON.stringify(acquisition.data),
      ],
    );
    const id = inserted.rows[0]!.id;
    for (let offset = 0; offset < snapshot.rows.length; offset += 1000) {
      const rows = snapshot.rows.slice(offset, offset + 1000).map((row) => ({
        cve: 'cveID' in row ? row.cveID : row.cve,
        evidence: row,
      }));
      await client.query(
        `INSERT INTO eq_feed_rows(snapshot_id,cve,evidence) SELECT $1,x.cve,x.evidence FROM jsonb_to_recordset($2::jsonb) AS x(cve text,evidence jsonb)`,
        [id, JSON.stringify(rows)],
      );
    }
    await client.query(
      `INSERT INTO eq_feed_active(source,snapshot_id) VALUES($1,$2) ON CONFLICT(source) DO UPDATE SET snapshot_id=EXCLUDED.snapshot_id`,
      [source, id],
    );
    const revision = await client.query<{ revision: number }>(
      'UPDATE eq_workspace SET revision=revision+1 WHERE id=1 RETURNING revision',
    );
    await client.query('COMMIT');
    return {
      snapshotId: id,
      revision: revision.rows[0]!.revision,
      rows: snapshot.rows.length,
    };
  } catch (error) {
    try {
      await client.query('ROLLBACK');
    } catch {
      broken = true;
    }
    throw error;
  } finally {
    client.release(broken);
  }
}
