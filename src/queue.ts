import type { Pool } from 'pg';
import { z } from 'zod';
import { StaleReview } from './store.js';

const requestSchema = z.strictObject({
  asOf: z.iso.date(),
  limit: z.number().int().min(1).max(100).default(50),
  after: z
    .strictObject({
      asset: z.string().min(1).max(128),
      cve: z.string().regex(/^CVE-[0-9]{4}-[0-9]{4,19}$/),
      revision: z.number().int().nonnegative(),
      asOf: z.iso.date(),
      criticality: z.string().nullable(),
      minEpss: z.number().nullable(),
    })
    .optional(),
  minEpss: z.number().min(0).max(1).optional(),
  criticality: z.enum(['low', 'medium', 'high', 'critical']).optional(),
});

/** Each page reads revision, findings and evidence from one MVCC snapshot. */
export async function readQueue(pool: Pool, request: unknown) {
  const options = requestSchema.parse(request);
  if (
    options.after &&
    (options.after.asOf !== options.asOf ||
      options.after.criticality !== (options.criticality ?? null) ||
      options.after.minEpss !== (options.minEpss ?? null))
  )
    throw new StaleReview('Queue filters changed; restart');
  const client = await pool.connect();
  let broken = false;
  try {
    await client.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
    const state = await client.query<{ revision: number }>(
      'SELECT revision FROM eq_workspace WHERE id=1',
    );
    const revision = state.rows[0]!.revision;
    if (options.after && options.after.revision !== revision)
      throw new StaleReview('Workspace changed; restart queue');
    const future = await client.query(
      'SELECT 1 FROM eq_feed_active a JOIN eq_feed_snapshots s ON s.id=a.snapshot_id WHERE s.published_on>$1::date LIMIT 1',
      [options.asOf],
    );
    if (future.rows.length)
      throw new RangeError('Review date precedes active evidence');
    const result = await client.query(
      `SELECT f.asset,f.cve,f.criticality,f.exposure,f.observed_on::text,
      w.revision,k.hash AS kev_hash,e.hash AS epss_hash,
      k.provenance AS kev_provenance,e.provenance AS epss_provenance,
      k.published_on::text AS kev_published_on,e.published_on::text AS epss_published_on,
      CASE WHEN k.id IS NULL THEN 'unavailable' WHEN kr.cve IS NULL THEN 'not-listed' ELSE 'listed' END AS kev_state,
      CASE WHEN e.id IS NULL THEN 'unavailable' WHEN er.cve IS NULL THEN 'missing' ELSE 'scored' END AS epss_state,
      er.evidence->>'epss' AS epss,
      $1::date-k.published_on AS kev_age_days,
      $1::date-e.published_on AS epss_age_days
    FROM eq_findings f CROSS JOIN eq_workspace w
    LEFT JOIN eq_feed_active ka ON ka.source='cisa-kev'
    LEFT JOIN eq_feed_snapshots k ON k.id=ka.snapshot_id
    LEFT JOIN eq_feed_rows kr ON kr.snapshot_id=k.id AND kr.cve=f.cve
    LEFT JOIN eq_feed_active ea ON ea.source='first-epss'
    LEFT JOIN eq_feed_snapshots e ON e.id=ea.snapshot_id
    LEFT JOIN eq_feed_rows er ON er.snapshot_id=e.id AND er.cve=f.cve
    WHERE ($2::text IS NULL OR f.criticality=$2)
      AND ($4::text IS NULL OR (f.asset,f.cve)>($4::text COLLATE "C",$5::text COLLATE "C"))
      AND ($6::double precision IS NULL OR (er.evidence->>'epss')::double precision >= $6)
    ORDER BY f.asset COLLATE "C",f.cve COLLATE "C" LIMIT $3`,
      [
        options.asOf,
        options.criticality ?? null,
        options.limit + 1,
        options.after?.asset ?? null,
        options.after?.cve ?? null,
        options.minEpss ?? null,
      ],
    );
    const rows = result.rows.slice(0, options.limit);
    const last = rows.at(-1);
    const next =
      result.rows.length > options.limit && last
        ? {
            asset: last.asset as string,
            cve: last.cve as string,
            revision,
            asOf: options.asOf,
            criticality: options.criticality ?? null,
            minEpss: options.minEpss ?? null,
          }
        : null;
    await client.query('COMMIT');
    return { revision, rows, next };
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
