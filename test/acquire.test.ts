import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { gzipSync } from 'node:zlib';
import { mkdtemp, rm, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  acquireArchives,
  downloadArchive,
  expandEpss,
  verifyBlob,
  SOURCES,
} from '../src/acquire.js';
import { FEED_MAX_BYTES } from '../src/feeds.js';

test('Git blob identity checks both exact bytes and length', () => {
  const bytes = Buffer.from('synthetic only');
  const hash = createHash('sha1')
    .update(`blob ${bytes.length}\0`)
    .update(bytes)
    .digest('hex');
  verifyBlob(bytes, bytes.length, hash);
  assert.throws(() =>
    verifyBlob(Buffer.from('synthetic Only'), bytes.length, hash),
  );
  assert.throws(() => verifyBlob(bytes, bytes.length + 1, hash));
});
test('gzip integrity, truncation and expansion limit are enforced', () => {
  const bytes = Buffer.from('synthetic only');
  assert.deepEqual(expandEpss(gzipSync(bytes)), bytes);
  assert.throws(() => expandEpss(gzipSync(bytes).subarray(0, 15)));
  assert.throws(() => expandEpss(gzipSync(Buffer.alloc(FEED_MAX_BYTES + 1))));
});
test('download uses fixed archive URL, refuses redirects/status and bad identities', async () => {
  const fake = (async (url, options) => {
    assert.equal(url, SOURCES.kev.url);
    assert.equal(options?.redirect, 'error');
    assert.equal(options?.credentials, 'omit');
    assert.ok(options?.signal);
    return new Response('synthetic', { status: 200 });
  }) as typeof fetch;
  await assert.rejects(downloadArchive('kev', fake), /identity/);
  for (const status of [302, 404, 500])
    await assert.rejects(
      downloadArchive(
        'kev',
        (async () => new Response('', { status })) as typeof fetch,
      ),
      /HTTP/,
    );
});
test('declared and streamed download byte caps refuse oversized bodies', async () => {
  await assert.rejects(
    downloadArchive(
      'epss',
      (async () =>
        new Response('', {
          headers: { 'content-length': '999999999' },
        })) as typeof fetch,
    ),
    /HTTP/,
  );
  let cancelled = false;
  const stream = new ReadableStream({
    pull(controller) {
      controller.enqueue(new Uint8Array(1024 * 1024));
    },
    cancel() {
      cancelled = true;
    },
  });
  await assert.rejects(
    downloadArchive('epss', (async () => new Response(stream)) as typeof fetch),
    /limit/,
  );
  assert.equal(cancelled, true);
});
test('existing destination is refused before any network or file mutation', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'eq-acquire-'));
  try {
    await writeFile(join(directory, 'keep'), 'unchanged');
    await assert.rejects(acquireArchives(directory, '2026-11-09'), {
      code: 'EEXIST',
    });
    assert.equal(await readFile(join(directory, 'keep'), 'utf8'), 'unchanged');
    await assert.rejects(
      acquireArchives(join(directory, 'invalid'), '2026-02-30'),
    );
  } finally {
    await rm(directory, { recursive: true });
  }
});

test('acquisition CLI reports safe domain failures and refuses extra arguments', async () => {
  const { spawnSync } = await import('node:child_process');
  const invalid = spawnSync(
    process.execPath,
    ['scripts/acquire-feeds.mjs', 'unused-directory', '2026-02-30'],
    { encoding: 'utf8' },
  );
  assert.equal(invalid.status, 2);
  assert.match(invalid.stderr, /Review day must be valid/);
  assert.doesNotMatch(invalid.stderr, /at acquireArchives/);
  const extra = spawnSync(
    process.execPath,
    ['scripts/acquire-feeds.mjs', 'unused', '2026-11-09', 'extra'],
    { encoding: 'utf8' },
  );
  assert.equal(extra.status, 2);
  assert.match(extra.stderr, /Usage:/);
});
