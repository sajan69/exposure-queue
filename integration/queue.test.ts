import test from 'node:test';
import assert from 'node:assert/strict';
import { Pool } from 'pg';
import { initialize, StaleReview } from '../src/store.js';
import { initializeFeeds, activateFeed } from '../src/feed-store.js';
import { parseEpss } from '../src/feeds.js';
import { readQueue } from '../src/queue.js';
if (!process.env.TEST_DATABASE_URL)
  throw new Error('TEST_DATABASE_URL required');
test('queue exact joins preserve zero, missing evidence, pagination and revision refusal', async () => {
  const pool = new Pool({ connectionString: process.env.TEST_DATABASE_URL });
  const client = await pool.connect();
  try {
    await client.query('CREATE SCHEMA queue_fixture');
    await client.query('SET search_path TO queue_fixture');
    const scoped = {
      query: client.query.bind(client),
      connect: async () => ({ query: client.query.bind(client), release() {} }),
    } as unknown as Pool;
    await initialize(scoped);
    await initializeFeeds(scoped);
    await client.query(
      "INSERT INTO eq_imports(sha256,reviewed_on,inserted) VALUES($1,'2026-11-09',2)",
      ['a'.repeat(64)],
    );
    await client.query(
      "INSERT INTO eq_findings VALUES ('alpha','CVE-2024-1234','2026-11-08','high','internal',1),('beta','CVE-2024-12345','2026-11-08','low','unknown',1)",
    );
    let page = await readQueue(scoped, { asOf: '2026-11-09', limit: 1 });
    assert.equal(page.rows[0]!.epss_state, 'unavailable');
    assert.equal(page.rows[0]!.kev_state, 'unavailable');
    const bytes = Buffer.from(
      '#model_version:v2026.06.15,score_date:2026-11-08\ncve,epss,percentile\nCVE-2024-1234,0,0\n',
    );
    await activateFeed(
      scoped,
      'first-epss',
      bytes,
      '2026-11-09',
      parseEpss(bytes, '2026-11-09').sha256,
      0,
      {
        url: 'https://example.invalid/fixture',
        retrievedAt: '2026-11-09T00:00:00Z',
        archiveSha256: 'b'.repeat(64),
      },
    );
    await assert.rejects(
      readQueue(scoped, { asOf: '2026-11-09', after: page.next }),
      StaleReview,
    );
    page = await readQueue(scoped, { asOf: '2026-11-09', limit: 1 });
    assert.equal(page.rows[0]!.epss, '0');
    assert.equal(
      page.rows[0]!.epss_hash,
      parseEpss(bytes, '2026-11-09').sha256,
    );
    assert.equal(
      (await readQueue(scoped, { asOf: '2026-11-09', minEpss: 0 })).rows.length,
      1,
    );
    assert.equal(
      (await readQueue(scoped, { asOf: '2026-11-09', minEpss: 0.1 })).rows
        .length,
      0,
    );
    assert.equal(page.rows[0]!.epss_state, 'scored');
    assert.equal(page.rows[0]!.epss_age_days, 1);
    const second = await readQueue(scoped, {
      asOf: '2026-11-09',
      limit: 1,
      after: page.next,
    });
    assert.equal(second.rows[0]!.cve, 'CVE-2024-12345');
    assert.equal(second.rows[0]!.epss_state, 'missing');
    assert.equal(second.next, null);
    assert.equal(
      (await readQueue(scoped, { asOf: '2026-11-09', criticality: 'high' }))
        .rows.length,
      1,
    );
    await assert.rejects(readQueue(scoped, { asOf: '2026-11-07' }), RangeError);
  } finally {
    await client.query('DROP SCHEMA queue_fixture CASCADE');
    client.release();
    await pool.end();
  }
});
