import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { pathToFileURL } from 'node:url';
import { join } from 'node:path';
import { loadWebAssets } from '../src/web-assets.js';
test('build loader refuses missing, unexpected and oversized files', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'eq-web-'));
  const root = pathToFileURL(dir + '/');
  try {
    await assert.rejects(loadWebAssets(root));
    await writeFile(join(dir, 'index.html'), '<h1>Queue</h1>');
    await mkdir(join(dir, 'assets'));
    await writeFile(join(dir, 'assets/app.js'), 'export {};');
    assert.equal((await loadWebAssets(root)).size, 2);
    await writeFile(join(dir, 'assets/private.txt'), 'not a web asset');
    await assert.rejects(loadWebAssets(root), /Unexpected web asset/);
    await rm(join(dir, 'assets/private.txt'));
    await writeFile(
      join(dir, 'assets/app.js'),
      Buffer.alloc(4 * 1024 * 1024 + 1),
    );
    await assert.rejects(loadWebAssets(root), /bounds/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
