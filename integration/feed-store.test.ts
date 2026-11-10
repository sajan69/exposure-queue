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
    const hash = parseEpss(bytes, '2026-11-09').sha256;
    const result = await activateFeed(
      dedicated,
      'first-epss',
      bytes,
      '2026-11-09',
      hash,
      0,
    );
    assert.equal(result.revision, 1);
    assert.equal(result.rows, 1);
    await assert.rejects(
      activateFeed(dedicated, 'first-epss', bytes, '2026-11-09', hash, 0),
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
      ),
      /same-day/,
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
