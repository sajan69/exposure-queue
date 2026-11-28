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

// Shared table checks also reject malformed direct-SQL writes. Application
// validation remains responsible for presenting useful input errors.
const decisionCheck = `CHECK (COALESCE(
  jsonb_typeof(decision)='object'
  AND decision ?& ARRAY['asset','cve','expectedRevision','owner','status','evidence','reviewedOn','exceptionUntil']
  AND (decision - ARRAY['asset','cve','expectedRevision','owner','status','evidence','reviewedOn','exceptionUntil'])='{}'::jsonb
  AND jsonb_typeof(decision->'asset')='string' AND decision->>'asset'=asset
  AND jsonb_typeof(decision->'cve')='string' AND decision->>'cve'=cve
  AND jsonb_typeof(decision->'expectedRevision')='number'
  AND decision->>'expectedRevision' ~ '^[0-9]+$'
  AND (decision->>'expectedRevision')::numeric BETWEEN 0 AND 2147483646
  AND jsonb_typeof(decision->'owner')='string'
  AND length(btrim(decision->>'owner')) BETWEEN 1 AND 128
  AND jsonb_typeof(decision->'evidence')='string'
  AND length(btrim(decision->>'evidence')) BETWEEN 1 AND 4096
  AND jsonb_typeof(decision->'status')='string'
  AND decision->>'status' IN ('open','investigating','resolved','exception')
  AND jsonb_typeof(decision->'reviewedOn')='string'
  AND decision->>'reviewedOn' ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}$'
  AND pg_input_is_valid(decision->>'reviewedOn','date')
  AND CASE WHEN decision->>'status'='exception' THEN
    jsonb_typeof(decision->'exceptionUntil')='string'
    AND decision->>'exceptionUntil' ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}$'
    AND pg_input_is_valid(decision->>'exceptionUntil','date')
    AND decision->>'exceptionUntil' > decision->>'reviewedOn'
  ELSE decision->'exceptionUntil'='null'::jsonb END,
  false))`;

export async function initializeTriage(pool: Pool) {
  await pool.query(`CREATE TABLE IF NOT EXISTS eq_decisions (
    asset text COLLATE "C" NOT NULL,cve text COLLATE "C" NOT NULL,
    decision jsonb NOT NULL ${decisionCheck},
    PRIMARY KEY(asset,cve),FOREIGN KEY(asset,cve) REFERENCES eq_findings(asset,cve)
  );
  CREATE TABLE IF NOT EXISTS eq_decision_events (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    asset text COLLATE "C" NOT NULL,cve text COLLATE "C" NOT NULL,
    revision integer NOT NULL UNIQUE CHECK(revision>0),
    decision jsonb NOT NULL ${decisionCheck},
    CHECK(revision=(decision->>'expectedRevision')::numeric+1),
    recorded_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY(asset,cve) REFERENCES eq_findings(asset,cve)
  );
  CREATE INDEX IF NOT EXISTS eq_decision_events_finding_revision
    ON eq_decision_events(asset,cve,revision);`);
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

const historySchema = z.strictObject({
  asset: readSchema.shape.asset,
  cve: readSchema.shape.cve,
  throughRevision: z.number().int().nonnegative(),
  afterRevision: z.number().int().nonnegative().default(0),
  limit: z.number().int().min(1).max(100).default(50),
});

/** Fixed upper revision excludes reviews appended after pagination starts. */
export async function readDecisionHistory(pool: Pool, input: unknown) {
  const request = historySchema.parse(input);
  if (request.afterRevision > request.throughRevision)
    throw new RangeError('History cursor exceeds upper revision');
  const result = await pool.query<{
    revision: number;
    decision: unknown;
    recorded_at: Date;
  }>(
    `SELECT revision,decision,recorded_at FROM eq_decision_events
     WHERE asset=$1 AND cve=$2 AND revision>$3 AND revision<=$4
     ORDER BY revision LIMIT $5`,
    [
      request.asset,
      request.cve,
      request.afterRevision,
      request.throughRevision,
      request.limit + 1,
    ],
  );
  const rows = result.rows.slice(0, request.limit).map((event) => ({
    ...event,
    decision: decisionSchema.parse(event.decision),
  }));
  return {
    rows,
    nextAfterRevision:
      result.rows.length > request.limit ? rows.at(-1)!.revision : null,
  };
}
