import { createHash } from 'node:crypto';
import { mkdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { gunzipSync } from 'node:zlib';
import { z } from 'zod';
import { FEED_MAX_BYTES, FeedError, parseKev, parseEpss } from './feeds.js';

// Reviewed archive identities; acquisition never resolves a moving branch.
export const SOURCES = Object.freeze({
  kev: Object.freeze({
    url: 'https://raw.githubusercontent.com/cisagov/kev-data/e5b3a9b25050a8da26c96266c5bfe438ee0bdebc/known_exploited_vulnerabilities.json',
    bytes: 1832349,
    blob: '9100b9e667514b65cd38edd4ceeacb4e3b1c40f2',
    filename: 'kev.json',
  }),
  epss: Object.freeze({
    url: 'https://raw.githubusercontent.com/empiricalsec/epss_scores/a14602d91346f3875c90d027824578b6b7eecc1d/2026/epss_scores-2026-11-08.csv.gz',
    bytes: 2818450,
    blob: '0b3ab0805a80e31746159f2d3e3ea3a08df96c06',
    filename: 'epss.csv.gz',
  }),
});
const DOWNLOAD_MAX_BYTES = 8 * 1024 * 1024;
export function verifyBlob(bytes: Uint8Array, size: number, expected: string) {
  const actual = createHash('sha1')
    .update(`blob ${bytes.byteLength}\0`)
    .update(bytes)
    .digest('hex');
  if (bytes.byteLength !== size || actual !== expected)
    throw new FeedError('Archive byte identity mismatch');
}
export function expandEpss(bytes: Uint8Array): Buffer {
  try {
    return gunzipSync(bytes, { maxOutputLength: FEED_MAX_BYTES });
  } catch {
    throw new FeedError('Invalid or oversized gzip archive');
  }
}
/** Transport seam is for trusted callers/tests, never a request-supplied URL. */
export async function downloadArchive(
  source: keyof typeof SOURCES,
  transport: typeof fetch = fetch,
): Promise<Buffer> {
  if (!Object.hasOwn(SOURCES, source)) throw new FeedError('Unknown archive');
  const response = await transport(SOURCES[source].url, {
    redirect: 'error',
    credentials: 'omit',
    signal: AbortSignal.timeout(30000),
    headers: { 'Accept-Encoding': 'identity' },
  });
  const declared = response.headers.get('content-length');
  if (
    response.status !== 200 ||
    !response.body ||
    (declared !== null &&
      (!/^[0-9]+$/.test(declared) || Number(declared) > DOWNLOAD_MAX_BYTES))
  ) {
    await response.body?.cancel();
    throw new FeedError('Archive HTTP response refused');
  }
  const chunks: Uint8Array[] = [];
  let total = 0;
  const reader = response.body.getReader();
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > DOWNLOAD_MAX_BYTES) {
        await reader.cancel();
        throw new FeedError('Archive download exceeds byte limit');
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const bytes = Buffer.concat(chunks, total);
  verifyBlob(bytes, SOURCES[source].bytes, SOURCES[source].blob);
  return bytes;
}
const sha256 = (bytes: Uint8Array) =>
  createHash('sha256').update(bytes).digest('hex');

/** Creates a new directory; existing or failed partial destinations are never reused. */
export async function acquireArchives(target: string, asOf: string) {
  if (!z.iso.date().safeParse(asOf).success || asOf < '2026-11-08')
    throw new FeedError('Review day must be valid and on/after archive day');
  await mkdir(target, { mode: 0o700 });
  const records = [];
  for (const source of ['kev', 'epss'] as const) {
    const startedAt = new Date().toISOString();
    const bytes = await downloadArchive(source);
    const retrievedAt = new Date().toISOString();
    const decoded = source === 'epss' ? expandEpss(bytes) : bytes;
    const snapshot =
      source === 'epss' ? parseEpss(decoded, asOf) : parseKev(decoded, asOf);
    if (source === 'epss' && snapshot.publishedOn !== '2026-11-08')
      throw new FeedError('EPSS archive publication day mismatch');
    await writeFile(join(target, SOURCES[source].filename), bytes, {
      flag: 'wx',
      mode: 0o600,
    });
    if (source === 'epss')
      await writeFile(join(target, 'epss.csv'), decoded, {
        flag: 'wx',
        mode: 0o600,
      });
    records.push({
      source: snapshot.source,
      url: SOURCES[source].url,
      gitBlobSha1: SOURCES[source].blob,
      startedAt,
      retrievedAt,
      archiveBytes: bytes.byteLength,
      archiveSha256: sha256(bytes),
      decodedBytes: snapshot.bytes,
      decodedSha256: snapshot.sha256,
      publishedOn: snapshot.publishedOn,
      publishedAt: snapshot.publishedAt,
      version: snapshot.version,
      rows: snapshot.rows.length,
    });
  }
  const summary = {
    protocol: 'official-archives-v1',
    complete: true,
    asOf,
    environment: {
      node: process.version,
      platform: process.platform,
      arch: process.arch,
    },
    attribution:
      'KEV: CISA, CC0 database. EPSS: FIRST EPSS SIG and Empirical Security; freely published scores, attribution requested.',
    records,
  };
  await writeFile(
    join(target, 'summary.json'),
    JSON.stringify(summary, null, 2) + '\n',
    {
      flag: 'wx',
      mode: 0o600,
    },
  );
  return summary;
}
