import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import pg from 'pg';
import { SOURCES, verifyBlob, expandEpss } from '../dist/src/acquire.js';
import { parseKev, parseEpss } from '../dist/src/feeds.js';
import { initialize } from '../dist/src/store.js';
import { initializeFeeds, activateFeed } from '../dist/src/feed-store.js';

// This verification owns a fresh schema in an explicitly disposable database.
assert.ok(process.env.TEST_DATABASE_URL, 'TEST_DATABASE_URL is required');
const directory = process.argv[2];
assert.ok(directory, 'Acquisition directory is required');
const summary = JSON.parse(
  await readFile(join(directory, 'summary.json'), 'utf8'),
);
const recorded = JSON.parse(
  await readFile('examples/feed-acquisition.json', 'utf8'),
);
assert.equal(summary.protocol, 'official-archives-v1');
assert.equal(summary.complete, true);
const stable = (record) =>
  Object.fromEntries(
    Object.entries(record).filter(
      ([key]) => !['startedAt', 'retrievedAt'].includes(key),
    ),
  );
assert.deepEqual(summary.records.map(stable), recorded.records.map(stable));
const inputs = [];
for (const key of ['kev', 'epss']) {
  const source = SOURCES[key];
  const archive = await readFile(join(directory, source.filename));
  verifyBlob(archive, source.bytes, source.blob);
  const bytes = key === 'epss' ? expandEpss(archive) : archive;
  const snapshot =
    key === 'epss'
      ? parseEpss(bytes, summary.asOf)
      : parseKev(bytes, summary.asOf);
  const record = summary.records.find((r) => r.source === snapshot.source);
  assert.ok(record);
  assert.equal(
    createHash('sha256').update(archive).digest('hex'),
    record.archiveSha256,
  );
  assert.equal(snapshot.sha256, record.decodedSha256);
  assert.equal(snapshot.rows.length, record.rows);
  inputs.push({ bytes, snapshot, record });
}
const pool = new pg.Pool({
  connectionString: process.env.TEST_DATABASE_URL,
  max: 1,
});
const client = await pool.connect();
let created = false;
try {
  await client.query('CREATE SCHEMA archive_store_verification');
  created = true;
  await client.query('SET search_path TO archive_store_verification');
  // All operations use this one connection and schema, including transactions.
  const scoped = {
    query: (...args) => client.query(...args),
    connect: async () => ({
      query: (...args) => client.query(...args),
      release() {},
    }),
  };
  await initialize(scoped);
  await initializeFeeds(scoped);
  const results = [];
  for (const [revision, { bytes, snapshot, record }] of inputs.entries()) {
    const provenance = {
      url: record.url,
      retrievedAt: record.retrievedAt,
      archiveSha256: record.archiveSha256,
    };
    const activated = await activateFeed(
      scoped,
      snapshot.source,
      bytes,
      summary.asOf,
      snapshot.sha256,
      revision,
      provenance,
    );
    assert.equal(activated.revision, revision + 1);
    const metadata = await client.query(
      'SELECT hash,published_on::text AS day,version,row_count,provenance FROM eq_feed_snapshots WHERE id=$1',
      [activated.snapshotId],
    );
    assert.deepEqual(metadata.rows, [
      {
        hash: snapshot.sha256,
        day: snapshot.publishedOn,
        version: snapshot.version,
        row_count: snapshot.rows.length,
        provenance,
      },
    ]);
    const expected = new Map(
      snapshot.rows.map((row) => ['cveID' in row ? row.cveID : row.cve, row]),
    );
    let after = '';
    let verified = 0;
    while (true) {
      const page = await client.query(
        'SELECT cve,evidence FROM eq_feed_rows WHERE snapshot_id=$1 AND cve>$2 COLLATE "C" ORDER BY cve LIMIT 2000',
        [activated.snapshotId, after],
      );
      if (!page.rows.length) break;
      for (const row of page.rows) {
        assert.deepEqual(row.evidence, expected.get(row.cve));
        expected.delete(row.cve);
        after = row.cve;
        verified++;
      }
    }
    assert.equal(expected.size, 0);
    assert.equal(verified, snapshot.rows.length);
    results.push({
      source: snapshot.source,
      decodedSha256: snapshot.sha256,
      verifiedRows: verified,
    });
  }
  const state = await client.query(
    'SELECT revision FROM eq_workspace WHERE id=1',
  );
  assert.equal(state.rows[0].revision, 2);
  const active = await client.query(
    'SELECT source FROM eq_feed_active ORDER BY source',
  );
  assert.deepEqual(
    active.rows.map((r) => r.source),
    ['cisa-kev', 'first-epss'],
  );
  console.log(
    JSON.stringify({
      complete: true,
      postgres: (await client.query('SHOW server_version')).rows[0]
        .server_version,
      results,
    }),
  );
} finally {
  if (created)
    await client.query('DROP SCHEMA archive_store_verification CASCADE');
  client.release();
  await pool.end();
}
