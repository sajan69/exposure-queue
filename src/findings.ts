import { createHash } from 'node:crypto';
import { parse } from 'csv-parse/sync';
import { z } from 'zod';

export const MAX_BYTES = 1024 * 1024;
export const MAX_ROWS = 1000;
export const HEADERS = [
  'asset',
  'cve',
  'observed_on',
  'criticality',
  'exposure',
] as const;
const date = z.iso.date();
const findingSchema = z.strictObject({
  asset: z
    .string()
    .min(1)
    .max(128)
    .regex(/^[A-Za-z0-9][A-Za-z0-9._:/-]*$/),
  cve: z.string().regex(/^CVE-[0-9]{4}-[0-9]{4,19}$/),
  observed_on: date,
  criticality: z.enum(['low', 'medium', 'high', 'critical']),
  exposure: z.enum(['internal', 'internet', 'unknown']),
});
export type Finding = z.infer<typeof findingSchema>;
export type Issue = { row: number; field: string; code: string };
export type Preview = {
  sha256: string;
  inputRows: number;
  findings: Finding[];
  duplicates: { row: number; firstRow: number }[];
  issues: Issue[];
  canConfirm: boolean;
};

export class ImportError extends Error {
  override name = 'ImportError';
}

/** Asset IDs stay case-sensitive; only the CVE prefix is normalized. */
export function previewFindings(input: Uint8Array, asOf: string): Preview {
  if (!date.safeParse(asOf).success)
    throw new ImportError('Invalid review date');
  if (input.byteLength === 0 || input.byteLength > MAX_BYTES)
    throw new ImportError('CSV must contain 1 to 1048576 bytes');
  let text: string;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(input);
  } catch {
    throw new ImportError('CSV must be valid UTF-8');
  }
  let rows: string[][];
  try {
    rows = parse(text, {
      bom: true,
      max_record_size: 4096,
      skip_empty_lines: false,
    }) as string[][];
  } catch {
    throw new ImportError('Malformed CSV or record exceeds 4096 characters');
  }
  if (JSON.stringify(rows[0]) !== JSON.stringify(HEADERS))
    throw new ImportError(
      'CSV headers must exactly match the documented order',
    );
  if (rows.length < 2 || rows.length > MAX_ROWS + 1)
    throw new ImportError('CSV must contain 1 to 1000 data records');
  const result: Preview = {
    sha256: createHash('sha256').update(input).digest('hex'),
    inputRows: rows.length - 1,
    findings: [],
    duplicates: [],
    issues: [],
    canConfirm: false,
  };
  const seen = new Map<string, { row: number; finding: Finding }>();
  for (const [index, cells] of rows.slice(1).entries()) {
    const row = index + 2; // logical CSV record, not physical line for quoted newlines
    const values = Object.fromEntries(
      HEADERS.map((key, i) => [key, cells[i]?.trim()]),
    );
    if (typeof values.cve === 'string') values.cve = values.cve.toUpperCase();
    const parsed = findingSchema.safeParse(values);
    if (!parsed.success) {
      result.issues.push(
        ...parsed.error.issues.map((issue) => ({
          row,
          field: String(issue.path[0]),
          code: 'invalid_value',
        })),
      );
      continue;
    }
    const finding = parsed.data;
    if (finding.observed_on > asOf) {
      result.issues.push({ row, field: 'observed_on', code: 'future_date' });
      continue;
    }
    const key = JSON.stringify([finding.asset, finding.cve]);
    const prior = seen.get(key);
    if (prior) {
      if (JSON.stringify(prior.finding) !== JSON.stringify(finding))
        result.issues.push({
          row,
          field: 'asset,cve',
          code: 'conflicting_duplicate',
        });
      else result.duplicates.push({ row, firstRow: prior.row });
    } else {
      seen.set(key, { row, finding });
      result.findings.push(finding);
    }
  }
  result.canConfirm = result.issues.length === 0 && result.findings.length > 0;
  return result;
}
