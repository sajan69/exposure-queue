import test from 'node:test';
import assert from 'node:assert/strict';
import { Pool } from 'pg';
import { parse } from 'csv-parse/sync';
import { initialize } from '../src/store.js';
import { initializeFeeds } from '../src/feed-store.js';
import { initializeTriage } from '../src/triage.js';
import { createApi } from '../src/api.js';
import { createLocalServer } from '../src/http-server.js';
import { listenLocal } from '../src/listen-local.js';
import { checkReadiness } from '../src/readiness.js';

if (!process.env.TEST_DATABASE_URL)
  throw new Error('TEST_DATABASE_URL required');
test('HTTP import review, atomic confirmation and stale refusal use PostgreSQL state', async () => {
  const pool = new Pool({ connectionString: process.env.TEST_DATABASE_URL });
  const client = await pool.connect();
  const scoped = {
    query: client.query.bind(client),
    connect: async () => ({ query: client.query.bind(client), release() {} }),
  } as unknown as Pool;
  const server = createLocalServer(createApi(scoped));
  let owned = false;
  try {
    await client.query('CREATE SCHEMA http_fixture');
    owned = true;
    await client.query('SET search_path TO http_fixture');
    await initialize(scoped);
    await assert.rejects(checkReadiness(scoped));
    await initializeFeeds(scoped);
    await initializeTriage(scoped);
    await checkReadiness(scoped);
    await client.query('DELETE FROM eq_workspace WHERE id=1');
    await assert.rejects(checkReadiness(scoped));
    await client.query('INSERT INTO eq_workspace (id, revision) VALUES (1, 0)');
    await checkReadiness(scoped);
    const port = await listenLocal(server, 0);
    const post = (path: string, body: unknown) =>
      fetch(`http://127.0.0.1:${port}${path}`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(body),
      });
    const input = {
      csv: 'asset,cve,observed_on,criticality,exposure\nalpha,CVE-2024-1234,2026-11-08,high,internal\n',
      asOf: '2026-11-09',
    };
    const reviewed = await post('/api/import/review', input);
    assert.equal(reviewed.status, 200);
    const preview = (await reviewed.json()) as {
      sha256: string;
      revision: number;
      canConfirm: boolean;
    };
    assert.equal(preview.canConfirm, true);
    const confirmation = {
      ...input,
      expectedHash: preview.sha256,
      expectedRevision: preview.revision,
    };
    const confirmed = await post('/api/import/confirm', confirmation);
    assert.equal(confirmed.status, 200);
    assert.deepEqual(await confirmed.json(), { inserted: 1, revision: 1 });
    assert.equal((await post('/api/import/confirm', confirmation)).status, 409);
    const pageResponse = await post('/api/queue', { asOf: input.asOf });
    assert.equal(pageResponse.status, 200);
    const page = (await pageResponse.json()) as {
      revision: number;
      rows: { asset: string }[];
    };
    assert.equal(page.revision, 1);
    assert.equal(page.rows[0]?.asset, 'alpha');
    const decision = {
      asset: 'alpha',
      cve: 'CVE-2024-1234',
      expectedRevision: 1,
      owner: 'Analyst',
      status: 'investigating',
      evidence: 'Synthetic review evidence',
      reviewedOn: input.asOf,
      exceptionUntil: null,
    };
    assert.equal((await post('/api/decision/save', decision)).status, 200);
    assert.equal((await post('/api/decision/save', decision)).status, 409);
    const read = await post('/api/decision/read', {
      asset: decision.asset,
      cve: decision.cve,
      asOf: input.asOf,
    });
    assert.equal(read.status, 200);
    const saved = (await read.json()) as {
      effectiveStatus: string;
      decision: { evidence: string };
    };
    assert.equal(saved.effectiveStatus, 'investigating');
    assert.equal(saved.decision.evidence, decision.evidence);
    const history = await post('/api/decision/history', {
      asset: decision.asset,
      cve: decision.cve,
      throughRevision: 2,
    });
    assert.equal(history.status, 200);
    const events = (await history.json()) as { rows: { revision: number }[] };
    assert.deepEqual(
      events.rows.map((row) => row.revision),
      [2],
    );
    const exported = await post('/api/export', { asOf: input.asOf });
    assert.equal(exported.status, 200);
    const output = (await exported.json()) as { revision: number; csv: string };
    assert.equal(output.revision, 2);
    const records = parse(output.csv, { columns: true }) as Record<
      string,
      string
    >[];
    assert.equal(records[0]?.owner, 'Analyst');
    assert.equal(records[0]?.evidence, decision.evidence);
    assert.equal(records[0]?.revision, '2');
    assert.equal(
      (await post('/api/export', { asOf: input.asOf, rows: [] })).status,
      400,
    );
    const extraInput = { ...input, csv: input.csv.replace('alpha,', 'beta,') };
    const extraReview = (await (
      await post('/api/import/review', extraInput)
    ).json()) as { sha256: string; revision: number };
    assert.equal(
      (
        await post('/api/import/confirm', {
          ...extraInput,
          expectedHash: extraReview.sha256,
          expectedRevision: extraReview.revision,
        })
      ).status,
      200,
    );
    const firstExport = (await (
      await post('/api/export', { asOf: input.asOf, limit: 1 })
    ).json()) as { csv: string; next: unknown };
    assert.ok(firstExport.next);
    assert.equal(
      (parse(firstExport.csv, { columns: true }) as Record<string, string>[])[0]
        ?.asset,
      'alpha',
    );
    const secondResponse = await post('/api/export', {
      asOf: input.asOf,
      limit: 1,
      after: firstExport.next,
    });
    assert.equal(secondResponse.status, 200);
    const secondExport = (await secondResponse.json()) as {
      csv: string;
      next: unknown;
    };
    assert.equal(
      (
        parse(secondExport.csv, { columns: true }) as Record<string, string>[]
      )[0]?.asset,
      'beta',
    );
    assert.equal(secondExport.next, null);
    assert.equal(
      (await post('/api/decision/save', { ...decision, expectedRevision: 3 }))
        .status,
      200,
    );
    assert.equal(
      (
        await post('/api/export', {
          asOf: input.asOf,
          limit: 1,
          after: firstExport.next,
        })
      ).status,
      409,
    );
    assert.equal((await post('/api/unknown', {})).status, 404);
    assert.equal((await post('/api/import/review', { rows: [] })).status, 400);
    assert.equal(
      (await client.query('SELECT count(*)::int AS n FROM eq_findings')).rows[0]
        .n,
      2,
    );
  } finally {
    server.closeAllConnections();
    if (server.listening)
      await new Promise<void>((resolve) => server.close(() => resolve()));
    if (owned) await client.query('DROP SCHEMA http_fixture CASCADE');
    client.release();
    await pool.end();
  }
});
