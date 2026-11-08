import type { Pool, PoolClient } from 'pg';
import { previewFindings, ImportError, type Preview } from './findings.js';

export class StaleReview extends Error {}
export class FindingConflict extends Error {}

// All application writes serialize on the singleton workspace row. Unique keys
// remain the final guard against direct SQL or future writers bypassing that lock.
export async function initialize(pool: Pool): Promise<void> {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS eq_workspace (
      id integer PRIMARY KEY CHECK (id = 1),
      revision integer NOT NULL CHECK (revision >= 0)
    );
    INSERT INTO eq_workspace VALUES (1, 0) ON CONFLICT DO NOTHING;
    CREATE TABLE IF NOT EXISTS eq_imports (
      id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
      sha256 text NOT NULL CHECK (sha256 ~ '^[a-f0-9]{64}$'),
      reviewed_on date NOT NULL,
      imported_at timestamptz NOT NULL DEFAULT now(),
      inserted integer NOT NULL CHECK (inserted >= 0)
    );
    CREATE TABLE IF NOT EXISTS eq_findings (
      asset text COLLATE "C" NOT NULL CHECK (length(asset) BETWEEN 1 AND 128 AND asset ~ '^[A-Za-z0-9][A-Za-z0-9._:/-]*$'),
      cve text COLLATE "C" NOT NULL CHECK (cve ~ '^CVE-[0-9]{4}-[0-9]{4,19}$'),
      observed_on date NOT NULL,
      criticality text NOT NULL CHECK (criticality IN ('low','medium','high','critical')),
      exposure text NOT NULL CHECK (exposure IN ('internal','internet','unknown')),
      import_id bigint NOT NULL REFERENCES eq_imports(id),
      PRIMARY KEY (asset, cve)
    );
  `);
}

export async function reviewImport(
  pool: Pool,
  bytes: Uint8Array,
  asOf: string,
): Promise<Preview & { revision: number }> {
  const preview = previewFindings(bytes, asOf);
  const state = await pool.query<{ revision: number }>(
    'SELECT revision FROM eq_workspace WHERE id=1',
  );
  if (state.rows.length !== 1) throw new Error('Workspace is not initialized');
  return { ...preview, revision: state.rows[0]!.revision };
}

async function insertFindings(
  client: PoolClient,
  preview: Preview,
  asOf: string,
): Promise<number> {
  const batch = await client.query<{ id: string }>(
    'INSERT INTO eq_imports (sha256,reviewed_on,inserted) VALUES ($1,$2,0) RETURNING id',
    [preview.sha256, asOf],
  );
  let inserted = 0;
  for (const finding of preview.findings) {
    const values = [
      finding.asset,
      finding.cve,
      finding.observed_on,
      finding.criticality,
      finding.exposure,
    ];
    const existing = await client.query<{ identical: boolean }>(
      `SELECT (observed_on=$3::date AND criticality=$4 AND exposure=$5) AS identical FROM eq_findings WHERE asset=$1 AND cve=$2`,
      values,
    );
    if (existing.rows.length) {
      if (!existing.rows[0]!.identical)
        throw new FindingConflict('Existing finding differs; review required');
      continue;
    }
    await client.query(
      'INSERT INTO eq_findings (asset,cve,observed_on,criticality,exposure,import_id) VALUES ($1,$2,$3,$4,$5,$6)',
      [...values, batch.rows[0]!.id],
    );
    inserted++;
  }
  await client.query('UPDATE eq_imports SET inserted=$1 WHERE id=$2', [
    inserted,
    batch.rows[0]!.id,
  ]);
  return inserted;
}

/** Reparse original bytes; never accept a caller's normalized rows/canConfirm. */
export async function confirmImport(
  pool: Pool,
  bytes: Uint8Array,
  asOf: string,
  expectedHash: string,
  expectedRevision: number,
): Promise<{ inserted: number; revision: number }> {
  if (!Number.isSafeInteger(expectedRevision) || expectedRevision < 0)
    throw new ImportError('Invalid workspace revision');
  const preview = previewFindings(bytes, asOf);
  if (!preview.canConfirm || preview.sha256 !== expectedHash)
    throw new ImportError('Input changed or validation failed');
  const client = await pool.connect();
  let broken = false;
  try {
    await client.query('BEGIN');
    await client.query("SET LOCAL lock_timeout = '5s'");
    const state = await client.query<{ revision: number }>(
      'SELECT revision FROM eq_workspace WHERE id=1 FOR UPDATE',
    );
    if (state.rows[0]?.revision !== expectedRevision)
      throw new StaleReview('Workspace changed; review again');
    const inserted = await insertFindings(client, preview, asOf);
    const result = await client.query<{ revision: number }>(
      'UPDATE eq_workspace SET revision=revision+1 WHERE id=1 RETURNING revision',
    );
    await client.query('COMMIT');
    return { inserted, revision: result.rows[0]!.revision };
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
