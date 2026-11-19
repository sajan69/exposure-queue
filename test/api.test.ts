import assert from 'node:assert/strict';
import test from 'node:test';
import type { Pool } from 'pg';
import { createApi } from '../src/api.js';

test('API refuses fabricated import projections and unknown routes before database access', async () => {
  const api = createApi({} as Pool);
  await assert.rejects(
    api('/api/import/review', { rows: [], asOf: '2026-11-20' }),
  );
  await assert.rejects(
    api('/api/import/confirm', {
      csv: '',
      asOf: '2026-11-20',
      expectedHash: 'x',
      expectedRevision: 0,
    }),
  );
  await assert.rejects(api('/api/unknown', {}), /Unknown API route/);
});
