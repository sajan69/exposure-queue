import test from 'node:test';
import assert from 'node:assert/strict';
import type { Pool } from 'pg';
import { recordDecision, readDecisionHistory } from '../src/triage.js';
test('invalid decisions refuse before connecting, including expired or misplaced exceptions', async () => {
  const pool = {
    connect() {
      throw new Error('Unexpected connection');
    },
  } as unknown as Pool;
  const base = {
    asset: 'host',
    cve: 'CVE-2024-1234',
    expectedRevision: 0,
    owner: 'analyst',
    status: 'exception',
    evidence: 'Synthetic review',
    reviewedOn: '2026-11-14',
    exceptionUntil: '2026-11-14',
  };
  for (const input of [
    base,
    { ...base, exceptionUntil: null },
    { ...base, status: 'resolved', exceptionUntil: '2026-11-15' },
    { ...base, owner: ' ' },
    { ...base, reviewedOn: '2026-02-30' },
  ])
    await assert.rejects(
      recordDecision(pool, input),
      (error: Error) => error.message !== 'Unexpected connection',
    );
});

test('history validates stored decisions before returning browser data', async () => {
  const decision = {
    asset: 'host',
    cve: 'CVE-2024-1234',
    expectedRevision: 0,
    owner: 'analyst',
    status: 'investigating',
    evidence: 'Synthetic evidence',
    reviewedOn: '2026-11-14',
    exceptionUntil: null,
  };
  let stored: unknown = decision;
  const pool = {
    query: async () => ({ rows: [{ revision: 1, decision: stored }] }),
  } as unknown as Pool;
  const request = { asset: 'host', cve: 'CVE-2024-1234', throughRevision: 1 };
  const page = await readDecisionHistory(pool, request);
  assert.deepEqual(page.rows[0]!.decision, decision);
  stored = { ...decision, status: 'unexpected' };
  await assert.rejects(readDecisionHistory(pool, request));
});
