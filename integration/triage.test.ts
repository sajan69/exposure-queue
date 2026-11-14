import test from 'node:test';
import assert from 'node:assert/strict';
import { Pool } from 'pg';
import { initialize, StaleReview } from '../src/store.js';
import {
  initializeTriage,
  recordDecision,
  readDecision,
} from '../src/triage.js';
if (!process.env.TEST_DATABASE_URL)
  throw new Error('TEST_DATABASE_URL required');
test('decision and history commit together; stale reviews and history failures preserve prior state', async () => {
  const pool = new Pool({ connectionString: process.env.TEST_DATABASE_URL });
  const client = await pool.connect();
  let created = false;
  try {
    await client.query('CREATE SCHEMA triage_fixture');
    created = true;
    await client.query('SET search_path TO triage_fixture');
    const scoped = {
      query: client.query.bind(client),
      connect: async () => ({ query: client.query.bind(client), release() {} }),
    } as unknown as Pool;
    await initialize(scoped);
    await initializeTriage(scoped);
    await client.query(
      "INSERT INTO eq_imports(sha256,reviewed_on,inserted) VALUES($1,'2026-11-14',1)",
      ['a'.repeat(64)],
    );
    await client.query(
      "INSERT INTO eq_findings VALUES('host','CVE-2024-1234','2026-11-14','high','internal',1)",
    );
    const decision = {
      asset: 'host',
      cve: 'CVE-2024-1234',
      expectedRevision: 0,
      owner: 'analyst',
      status: 'investigating',
      evidence: 'Synthetic review',
      reviewedOn: '2026-11-14',
      exceptionUntil: null,
    };
    assert.deepEqual(await recordDecision(scoped, decision), { revision: 1 });
    await assert.rejects(recordDecision(scoped, decision), StaleReview);
    assert.deepEqual(
      (await client.query('SELECT decision FROM eq_decisions')).rows,
      [{ decision }],
    );
    await client.query(
      "CREATE FUNCTION reject_event() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture event failure'; END $$",
    );
    await client.query(
      'CREATE TRIGGER reject_event BEFORE INSERT ON eq_decision_events FOR EACH ROW EXECUTE FUNCTION reject_event()',
    );
    await assert.rejects(
      recordDecision(scoped, {
        ...decision,
        expectedRevision: 1,
        status: 'resolved',
      }),
      /fixture event failure/,
    );
    assert.deepEqual(
      (await client.query('SELECT decision FROM eq_decisions')).rows,
      [{ decision }],
    );
    assert.equal(
      (await client.query('SELECT revision FROM eq_workspace')).rows[0]
        .revision,
      1,
    );
    assert.equal(
      (await client.query('SELECT count(*)::int AS n FROM eq_decision_events'))
        .rows[0].n,
      1,
    );
    await client.query('DROP TRIGGER reject_event ON eq_decision_events');
    const exception = {
      ...decision,
      expectedRevision: 1,
      status: 'exception',
      exceptionUntil: '2026-11-16',
    };
    await recordDecision(scoped, exception);
    for (const [asOf, expired] of [
      ['2026-11-15', false],
      ['2026-11-16', true],
      ['2026-11-17', true],
    ] as const) {
      const read = await readDecision(scoped, {
        asset: 'host',
        cve: decision.cve,
        asOf,
      });
      assert.equal(read?.exceptionExpired, expired);
      assert.equal(read?.effectiveStatus, expired ? 'open' : 'exception');
      assert.deepEqual(read?.decision, exception);
    }
    await assert.rejects(
      readDecision(scoped, {
        asset: 'host',
        cve: decision.cve,
        asOf: '2026-11-13',
      }),
      RangeError,
    );
    assert.equal(
      (await client.query('SELECT count(*)::int AS n FROM eq_decision_events'))
        .rows[0].n,
      2,
    );

    await assert.rejects(
      recordDecision(scoped, {
        ...decision,
        expectedRevision: 1,
        asset: 'missing',
      }),
      { code: '23503' },
    );
    assert.equal(
      (await client.query('SELECT revision FROM eq_workspace')).rows[0]
        .revision,
      2,
    );
  } finally {
    if (created) await client.query('DROP SCHEMA triage_fixture CASCADE');
    client.release();
    await pool.end();
  }
});

test('separate connections compete for one decision revision', async () => {
  const admin = new Pool({ connectionString: process.env.TEST_DATABASE_URL });
  await admin.query('CREATE SCHEMA triage_race');
  const pool = new Pool({
    connectionString: process.env.TEST_DATABASE_URL,
    max: 2,
    options: '-c search_path=triage_race',
  });
  try {
    await initialize(pool);
    await initializeTriage(pool);
    await pool.query(
      "INSERT INTO eq_imports(sha256,reviewed_on,inserted) VALUES($1,'2026-11-14',1)",
      ['a'.repeat(64)],
    );
    await pool.query(
      "INSERT INTO eq_findings VALUES('host','CVE-2024-1234','2026-11-14','high','internal',1)",
    );
    const clients = await Promise.all([pool.connect(), pool.connect()]);
    try {
      const pids = await Promise.all(
        clients.map((c) => c.query('SELECT pg_backend_pid() AS pid')),
      );
      assert.notEqual(pids[0]!.rows[0].pid, pids[1]!.rows[0].pid);
      const decision = {
        asset: 'host',
        cve: 'CVE-2024-1234',
        expectedRevision: 0,
        owner: 'analyst',
        status: 'open',
        evidence: 'Synthetic race',
        reviewedOn: '2026-11-14',
        exceptionUntil: null,
      };
      const outcomes = await Promise.allSettled(
        clients.map((c) =>
          recordDecision(
            {
              connect: async () => ({ query: c.query.bind(c), release() {} }),
            } as unknown as Pool,
            decision,
          ),
        ),
      );
      assert.equal(outcomes.filter((r) => r.status === 'fulfilled').length, 1);
      const refusal = outcomes.find((r) => r.status === 'rejected');
      assert.ok(
        refusal?.status === 'rejected' && refusal.reason instanceof StaleReview,
      );
    } finally {
      clients.forEach((c) => c.release());
    }
    assert.equal(
      (await pool.query('SELECT revision FROM eq_workspace')).rows[0].revision,
      1,
    );
    assert.equal(
      (await pool.query('SELECT count(*)::int AS n FROM eq_decisions')).rows[0]
        .n,
      1,
    );
    assert.equal(
      (await pool.query('SELECT count(*)::int AS n FROM eq_decision_events'))
        .rows[0].n,
      1,
    );
  } finally {
    await pool.end();
    await admin.query('DROP SCHEMA triage_race CASCADE');
    await admin.end();
  }
});
