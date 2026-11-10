import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Pool } from 'pg';
import { initialize, StaleReview } from '../src/store.js';
import { initializeFeeds, activateFeed } from '../src/feed-store.js';
import { parseEpss } from '../src/feeds.js';
if (!process.env.TEST_DATABASE_URL)
  throw new Error('TEST_DATABASE_URL required');
test('feed activation atomically advances revision and refuses stale or conflicting evidence', async () => {
  const pool = new Pool({ connectionString: process.env.TEST_DATABASE_URL });
  const schema = 'feed_activation_test';
  const client = await pool.connect();
  try {
    await client.query(`CREATE SCHEMA ${schema}`);
    await client.query(`SET search_path TO ${schema}`);
    // A dedicated single-client pool facade isolates this fixture from import tests.
    const dedicated = {
      query: client.query.bind(client),
      connect: async () => ({
        query: client.query.bind(client),
        release: () => {},
      }),
    } as unknown as Pool;
    await initialize(dedicated);
    await initializeFeeds(dedicated);
    const bytes = Buffer.from(
      '#model_version:v2026.06.15,score_date:2026-11-08T12:00:26Z\ncve,epss,percentile\nCVE-2024-1234,0,0\n',
    );
    const provenance = {
      url: 'https://example.invalid/synthetic-epss.csv',
      retrievedAt: '2026-11-09T13:00:00Z',
      archiveSha256: 'a'.repeat(64),
    };
    const hash = parseEpss(bytes, '2026-11-09').sha256;
    const result = await activateFeed(
      dedicated,
      'first-epss',
      bytes,
      '2026-11-09',
      hash,
      0,
      provenance,
    );
    assert.equal(result.revision, 1);
    assert.equal(result.rows, 1);
    await assert.rejects(
      activateFeed(
        dedicated,
        'first-epss',
        bytes,
        '2026-11-09',
        hash,
        0,
        provenance,
      ),
      StaleReview,
    );
    const changed = Buffer.from(bytes.toString().replace(',0,0', ',0.5,0'));
    await assert.rejects(
      activateFeed(
        dedicated,
        'first-epss',
        changed,
        '2026-11-09',
        parseEpss(changed, '2026-11-09').sha256,
        1,
        provenance,
      ),
      /same-day/,
    );
    assert.deepEqual(
      (await client.query('SELECT provenance FROM eq_feed_snapshots')).rows[0]
        .provenance,
      provenance,
    );
    // Fail the second insert batch after 1,000 rows have reached PostgreSQL.
    await client.query(`CREATE FUNCTION refuse_fixture() RETURNS trigger LANGUAGE plpgsql AS $$
      BEGIN IF NEW.cve='CVE-2024-11000' THEN RAISE EXCEPTION 'fixture failure'; END IF; RETURN NEW; END $$;
      CREATE TRIGGER refuse_fixture BEFORE INSERT ON eq_feed_rows FOR EACH ROW EXECUTE FUNCTION refuse_fixture()`);
    const larger = Buffer.from(
      '#model_version:v2026.06.15,score_date:2026-11-09T12:00:00Z\ncve,epss,percentile\n' +
        Array.from(
          { length: 1001 },
          (_, i) => `CVE-2024-${10000 + i},0.1,0.2`,
        ).join('\n') +
        '\n',
    );
    await assert.rejects(
      activateFeed(
        dedicated,
        'first-epss',
        larger,
        '2026-11-09',
        parseEpss(larger, '2026-11-09').sha256,
        1,
        provenance,
      ),
      /fixture failure/,
    );
    assert.equal(
      (await client.query('SELECT count(*)::int AS n FROM eq_feed_rows'))
        .rows[0].n,
      1,
    );
    assert.equal(
      (await client.query('SELECT snapshot_id::text AS id FROM eq_feed_active'))
        .rows[0].id,
      result.snapshotId,
    );
    assert.equal(
      (await client.query('SELECT count(*)::int AS n FROM eq_feed_snapshots'))
        .rows[0].n,
      1,
    );
    assert.equal(
      (await client.query('SELECT revision FROM eq_workspace')).rows[0]
        .revision,
      1,
    );
  } finally {
    await client.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);
    client.release();
    await pool.end();
  }
});
