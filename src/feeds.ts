import { createHash } from 'node:crypto';
import { parse } from 'csv-parse/sync';
import { z } from 'zod';

export const FEED_MAX_BYTES = 64 * 1024 * 1024;
const cveSchema = z.string().regex(/^CVE-[0-9]{4}-[0-9]{4,19}$/);
const daySchema = z.iso.date();
const text = z.string().max(16384);
const kevRow = z.strictObject({
  cveID: cveSchema,
  vendorProject: text,
  product: text,
  vulnerabilityName: text,
  dateAdded: daySchema,
  shortDescription: text,
  requiredAction: text,
  dueDate: daySchema,
  knownRansomwareCampaignUse: z.enum(['Known', 'Unknown']).optional(),
  forensicTriage: z.enum(['Yes', 'No']).optional(),
  notes: text.optional(),
  cwes: z
    .array(z.string().regex(/^CWE-[0-9]+$/))
    .max(100)
    .optional(),
});
export type KevRow = z.infer<typeof kevRow>;
export type EpssRow = { cve: string; epss: number; percentile: number };
export type Snapshot<T> = {
  source: 'cisa-kev' | 'first-epss';
  sha256: string;
  bytes: number;
  publishedOn: string;
  version: string;
  rows: T[];
};
export class FeedError extends Error {
  override name = 'FeedError';
}
function decode(bytes: Uint8Array): string {
  if (!bytes.byteLength || bytes.byteLength > FEED_MAX_BYTES)
    throw new FeedError('Feed size outside 1..67108864 bytes');
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    throw new FeedError('Feed must be UTF-8');
  }
}
function checkDay(day: string, asOf: string): void {
  if (
    !daySchema.safeParse(asOf).success ||
    !daySchema.safeParse(day).success ||
    day > asOf
  )
    throw new FeedError('Invalid or future snapshot date');
}
function unique<T>(rows: T[], key: (row: T) => string): void {
  const seen = new Set<string>();
  for (const row of rows) {
    const id = key(row);
    if (seen.has(id)) throw new FeedError('Duplicate CVE in snapshot');
    seen.add(id);
  }
}
function record<T>(
  bytes: Uint8Array,
  source: Snapshot<T>['source'],
  publishedOn: string,
  version: string,
  rows: T[],
): Snapshot<T> {
  return {
    source,
    sha256: createHash('sha256').update(bytes).digest('hex'),
    bytes: bytes.byteLength,
    publishedOn,
    version,
    rows,
  };
}
export function parseKev(bytes: Uint8Array, asOf: string): Snapshot<KevRow> {
  let input: unknown;
  try {
    input = JSON.parse(decode(bytes));
  } catch {
    throw new FeedError('Invalid KEV JSON');
  }
  const parsed = z
    .strictObject({
      title: text.optional(),
      catalogVersion: z.string().min(1).max(128),
      dateReleased: z.iso.datetime(),
      count: z.number().int().min(1).max(10000),
      vulnerabilities: z.array(kevRow).min(1).max(10000),
    })
    .safeParse(input);
  if (!parsed.success) throw new FeedError('Invalid KEV schema');
  const data = parsed.data;
  const day = data.dateReleased.slice(0, 10);
  checkDay(day, asOf);
  if (data.count !== data.vulnerabilities.length)
    throw new FeedError('KEV count mismatch');
  for (const row of data.vulnerabilities)
    if (row.dateAdded > day || row.dueDate < row.dateAdded)
      throw new FeedError('Inconsistent KEV dates');
  unique(data.vulnerabilities, (row) => row.cveID);
  return record(
    bytes,
    'cisa-kev',
    day,
    data.catalogVersion,
    data.vulnerabilities,
  );
}
export function parseEpss(bytes: Uint8Array, asOf: string): Snapshot<EpssRow> {
  const input = decode(bytes);
  const lineEnd = input.indexOf('\n');
  const metadata =
    /^#model_version:(v[0-9]{4}\.[0-9]{2}\.[0-9]{2}),score_date:([0-9]{4}-[0-9]{2}-[0-9]{2})\r?$/.exec(
      input.slice(0, lineEnd),
    );
  if (!metadata) throw new FeedError('Missing EPSS model/date metadata');
  const version = metadata[1]!;
  const day = metadata[2]!;
  checkDay(day, asOf);
  if (!daySchema.safeParse(version.slice(1).replaceAll('.', '-')).success)
    throw new FeedError('Invalid EPSS model version');
  let records: string[][];
  try {
    records = parse(input.slice(lineEnd + 1), {
      max_record_size: 256,
    }) as string[][];
  } catch {
    throw new FeedError('Invalid EPSS CSV');
  }
  if (
    JSON.stringify(records[0]) !==
      JSON.stringify(['cve', 'epss', 'percentile']) ||
    records.length < 2 ||
    records.length > 1000001
  )
    throw new FeedError('Invalid EPSS header or row count');
  const decimal = /^(?:0(?:\.[0-9]{1,20})?|1(?:\.0{1,20})?)$/;
  const rows = records.slice(1).map((cells) => {
    const [cve, score, percentile] = cells;
    if (
      cells.length !== 3 ||
      !cveSchema.safeParse(cve).success ||
      !score ||
      !percentile ||
      !decimal.test(score) ||
      !decimal.test(percentile)
    )
      throw new FeedError('Invalid EPSS row');
    return { cve: cve!, epss: Number(score), percentile: Number(percentile) };
  });
  unique(rows, (row) => row.cve);
  return record(bytes, 'first-epss', day, version, rows);
}

/** Missing snapshots and missing keys stay distinct; a zero score is data. */
export function joinEvidence(
  cves: readonly string[],
  kev: Snapshot<KevRow> | null,
  epss: Snapshot<EpssRow> | null,
  asOf: string,
) {
  checkDay(asOf, asOf);
  for (const snapshot of [kev, epss])
    if (snapshot) checkDay(snapshot.publishedOn, asOf);
  const kevById = new Map(kev?.rows.map((row) => [row.cveID, row]));
  const epssById = new Map(epss?.rows.map((row) => [row.cve, row]));
  return cves.map((cve) => {
    if (!cveSchema.safeParse(cve).success)
      throw new FeedError('Invalid join CVE');
    return {
      cve,
      kev: kev ? (kevById.get(cve) ?? null) : null,
      epss: epss ? (epssById.get(cve) ?? null) : null,
      kevState: !kev
        ? 'unavailable'
        : kevById.has(cve)
          ? 'listed'
          : 'not-listed',
      epssState: !epss
        ? 'unavailable'
        : epssById.has(cve)
          ? 'scored'
          : 'missing',
      kevAgeDays: kev ? age(kev.publishedOn, asOf) : null,
      epssAgeDays: epss ? age(epss.publishedOn, asOf) : null,
    };
  });
}
function age(day: string, asOf: string): number {
  return (Date.parse(asOf) - Date.parse(day)) / 86400000;
}
