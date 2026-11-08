import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Pool } from 'pg';
import {
  initialize,
  reviewImport,
  confirmImport,
  StaleReview,
  FindingConflict,
} from '../src/store.js';
const header = 'asset,cve,observed_on,criticality,exposure\n';
const row = 'web-01,CVE-2021-44228,2026-11-01,critical,internet';
const bytes = Buffer.from(header + row);
const date = '2026-11-08';
if (!process.env.TEST_DATABASE_URL)
  throw new Error('TEST_DATABASE_URL required; use a disposable database');
const pool = new Pool({
  connectionString: process.env.TEST_DATABASE_URL,
  max: 4,
});
test('PostgreSQL import lifecycle, rollback, constraints and competing confirmation', async () => {
  try {
    await initialize(pool);
    const initial = await reviewImport(pool, bytes, date);
    assert.equal(initial.revision, 0);
    assert.deepEqual(
      await confirmImport(pool, bytes, date, initial.sha256, 0),
      { inserted: 1, revision: 1 },
    );
    await assert.rejects(
      confirmImport(pool, bytes, date, initial.sha256, 0),
      StaleReview,
    );
    const repeated = await reviewImport(pool, bytes, date);
    assert.equal(
      (
        await confirmImport(
          pool,
          bytes,
          date,
          repeated.sha256,
          repeated.revision,
        )
      ).inserted,
      0,
    );
    // Insert a new row first, then encounter a conflict: the new row and batch must roll back.
    const conflict = Buffer.from(
      header +
        row.replace('web-01', 'new-asset') +
        '\n' +
        row.replace('critical', 'low'),
    );
    const reviewed = await reviewImport(pool, conflict, date);
    await assert.rejects(
      confirmImport(pool, conflict, date, reviewed.sha256, reviewed.revision),
      FindingConflict,
    );
    assert.equal(
      (await pool.query('SELECT count(*)::int AS n FROM eq_findings')).rows[0]
        .n,
      1,
    );
    assert.equal(
      (await pool.query('SELECT count(*)::int AS n FROM eq_imports')).rows[0].n,
      2,
    );
    assert.equal((await reviewImport(pool, bytes, date)).revision, 2);
    await assert.rejects(
      confirmImport(
        pool,
        Buffer.from(header + row + '\n'),
        date,
        initial.sha256,
        2,
      ),
    );
    const candidates = ['other-a', 'other-b'].map((asset) =>
      Buffer.from(header + row.replace('web-01', asset)),
    );
    const previews = await Promise.all(
      candidates.map((input) => reviewImport(pool, input, date)),
    );
    const races = await Promise.allSettled(
      candidates.map((input, i) =>
        confirmImport(
          pool,
          input,
          date,
          previews[i]!.sha256,
          previews[i]!.revision,
        ),
      ),
    );
    assert.equal(races.filter((r) => r.status === 'fulfilled').length, 1);
    const rejected = races.find((r) => r.status === 'rejected');
    assert.ok(
      rejected?.status === 'rejected' && rejected.reason instanceof StaleReview,
    );
    assert.equal(
      (await pool.query('SELECT count(*)::int AS n FROM eq_findings')).rows[0]
        .n,
      2,
    );
    await assert.rejects(
      pool.query(
        'INSERT INTO eq_findings SELECT asset,cve,observed_on,criticality,exposure,import_id FROM eq_findings LIMIT 1',
      ),
      { code: '23505' },
    );
    await assert.rejects(
      pool.query("UPDATE eq_findings SET exposure='invalid'"),
      { code: '23514' },
    );
    console.log(
      'PostgreSQL version',
      (await pool.query('SHOW server_version')).rows[0].server_version,
    );
  } finally {
    await pool.end();
  }
});
