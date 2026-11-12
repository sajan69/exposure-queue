import test from 'node:test';
import assert from 'node:assert/strict';
import type { Pool } from 'pg';
import { readQueue } from '../src/queue.js';

test('queue refuses invalid dates, bounds and unknown filters before SQL', async () => {
  const pool = {
    query() {
      throw new Error('SQL must not run');
    },
  } as unknown as Pool;
  for (const request of [
    { asOf: '2026-02-30' },
    { asOf: '2026-11-12', limit: 101 },
    { asOf: '2026-11-12', criticality: "high' OR true--" },
    { asOf: '2026-11-12', offset: 2 },
  ]) {
    await assert.rejects(
      readQueue(pool, request),
      (error: Error) => error.message !== 'SQL must not run',
    );
  }
});
