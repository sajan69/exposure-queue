import type { Pool } from 'pg';
import { RouteNotFound } from './http-errors.js';
import { z } from 'zod';
import { reviewImport, confirmImport } from './store.js';
import { readQueue } from './queue.js';
import { readDecision, readDecisionHistory, recordDecision } from './triage.js';

const importRequest = z.strictObject({
  csv: z.string().max(1024 * 1024),
  asOf: z.iso.date(),
});

/** Routes reuse domain validation and never accept normalized import rows. */
export function createApi(pool: Pool) {
  return async (path: string, body: unknown): Promise<unknown> => {
    switch (path) {
      case '/api/import/review': {
        const input = importRequest.parse(body);
        return reviewImport(pool, Buffer.from(input.csv, 'utf8'), input.asOf);
      }
      case '/api/import/confirm': {
        const input = importRequest
          .extend({
            expectedHash: z.string().regex(/^[a-f0-9]{64}$/),
            expectedRevision: z.number().int().nonnegative(),
          })
          .parse(body);
        return confirmImport(
          pool,
          Buffer.from(input.csv, 'utf8'),
          input.asOf,
          input.expectedHash,
          input.expectedRevision,
        );
      }
      case '/api/queue':
        return readQueue(pool, body);
      case '/api/decision/read':
        return readDecision(pool, body);
      case '/api/decision/history':
        return readDecisionHistory(pool, body);
      case '/api/decision/save':
        return recordDecision(pool, body);
      default:
        throw new RouteNotFound('Unknown API route');
    }
  };
}
