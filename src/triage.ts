import type { Pool } from 'pg';
import { z } from 'zod';
import { StaleReview } from './store.js';

const decisionSchema = z
  .strictObject({
    asset: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/),
    cve: z.string().regex(/^CVE-[0-9]{4}-[0-9]{4,19}$/),
    expectedRevision: z.number().int().nonnegative(),
    owner: z.string().trim().min(1).max(128),
    status: z.enum(['open', 'investigating', 'resolved', 'exception']),
    evidence: z.string().trim().min(1).max(4096),
    reviewedOn: z.iso.date(),
    exceptionUntil: z.iso.date().nullable(),
  })
  .superRefine((value, context) => {
    if (
      value.status === 'exception'
        ? !value.exceptionUntil || value.exceptionUntil <= value.reviewedOn
        : value.exceptionUntil !== null
    )
      context.addIssue({
        code: 'custom',
        message:
          'Exception requires a future expiry; other statuses require null',
      });
  });

export async function initializeTriage(pool: Pool) {
  await pool.query(`CREATE TABLE IF NOT EXISTS eq_decisions (
    asset text COLLATE "C" NOT NULL,cve text COLLATE "C" NOT NULL,
    decision jsonb NOT NULL CHECK(jsonb_typeof(decision)='object'),
    PRIMARY KEY(asset,cve),FOREIGN KEY(asset,cve) REFERENCES eq_findings(asset,cve)
  );
  CREATE TABLE IF NOT EXISTS eq_decision_events (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    asset text COLLATE "C" NOT NULL,cve text COLLATE "C" NOT NULL,
    revision integer NOT NULL UNIQUE,
    decision jsonb NOT NULL CHECK(jsonb_typeof(decision)='object'),
    recorded_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY(asset,cve) REFERENCES eq_findings(asset,cve)
  );`);
}

/** Owner is a local label, not an authenticated identity. */
export async function recordDecision(pool: Pool, input: unknown) {
  const decision = decisionSchema.parse(input);
  const client = await pool.connect();
  let broken = false;
  try {
    await client.query('BEGIN');
    await client.query("SET LOCAL lock_timeout='5s'");
    const state = await client.query<{ revision: number }>(
      'SELECT revision FROM eq_workspace WHERE id=1 FOR UPDATE',
    );
    if (state.rows[0]?.revision !== decision.expectedRevision)
      throw new StaleReview('Workspace changed; review again');
    const revision = decision.expectedRevision + 1;
    await client.query(
      'INSERT INTO eq_decisions(asset,cve,decision) VALUES($1,$2,$3) ON CONFLICT(asset,cve) DO UPDATE SET decision=EXCLUDED.decision',
      [decision.asset, decision.cve, JSON.stringify(decision)],
    );
    await client.query(
      'INSERT INTO eq_decision_events(asset,cve,revision,decision) VALUES($1,$2,$3,$4)',
      [decision.asset, decision.cve, revision, JSON.stringify(decision)],
    );
    await client.query('UPDATE eq_workspace SET revision=$1 WHERE id=1', [
      revision,
    ]);
    await client.query('COMMIT');
    return { revision };
  } catch (error) {
    try {
      await client.query('ROLLBACK');
    } catch {
      broken = true;
    }
    throw error;
  } finally {
    client.release(broken);
  }
}

const readSchema = z.strictObject({
  asset: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/),
  cve: z.string().regex(/^CVE-[0-9]{4}-[0-9]{4,19}$/),
  asOf: z.iso.date(),
});

/** Reads current saved state, not a reconstruction of historical decisions. */
export async function readDecision(pool: Pool, input: unknown) {
  const request = readSchema.parse(input);
  const result = await pool.query<{ decision: z.infer<typeof decisionSchema> }>(
    'SELECT decision FROM eq_decisions WHERE asset=$1 AND cve=$2',
    [request.asset, request.cve],
  );
  const saved = result.rows[0]?.decision;
  if (!saved) return null;
  const decision = decisionSchema.parse(saved);
  if (request.asOf < decision.reviewedOn)
    throw new RangeError('Read date precedes current decision');
  const expired =
    decision.status === 'exception' && decision.exceptionUntil! <= request.asOf;
  return {
    decision,
    exceptionExpired: expired,
    effectiveStatus: expired ? 'open' : decision.status,
  };
}
