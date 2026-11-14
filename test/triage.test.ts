import test from 'node:test';
import assert from 'node:assert/strict';
import type { Pool } from 'pg';
import { recordDecision } from '../src/triage.js';
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
