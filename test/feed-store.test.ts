import { test } from 'node:test';
import assert from 'node:assert/strict';
import type { Pool } from 'pg';
import { activateFeed } from '../src/feed-store.js';
test('invalid provenance refuses before a database connection is acquired', async () => {
  let connections = 0;
  const pool = {
    connect: async () => {
      connections++;
      throw new Error('must not connect');
    },
  } as unknown as Pool;
  const valid = {
    url: 'https://example.invalid/feed',
    retrievedAt: '2026-11-09T00:00:00Z',
    archiveSha256: 'a'.repeat(64),
  };
  for (const provenance of [
    { ...valid, url: 'http://example.invalid/feed' },
    { ...valid, url: 'https://user:password@example.invalid/feed' },
    { ...valid, retrievedAt: '2026-02-30T00:00:00Z' },
    { ...valid, archiveSha256: 'not-a-hash' },
    { ...valid, unexpected: 'refuse' },
  ])
    await assert.rejects(
      activateFeed(
        pool,
        'first-epss',
        new Uint8Array(),
        '2026-11-09',
        'a'.repeat(64),
        0,
        provenance,
      ),
      /provenance/,
    );
  assert.equal(connections, 0);
});
