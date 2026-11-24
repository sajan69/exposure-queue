import { open, readdir } from 'node:fs/promises';
import type { WebAsset } from './http-server.js';

/** Load trusted local build output; request paths never reach the filesystem. */
export async function loadWebAssets(root: URL): Promise<Map<string, WebAsset>> {
  const assets = new Map<string, WebAsset>();
  let total = 0;
  async function add(path: string, file: URL, contentType: string) {
    const handle = await open(file, 'r');
    try {
      const stat = await handle.stat();
      if (
        !stat.isFile() ||
        stat.size > 4 * 1024 * 1024 ||
        total + stat.size > 8 * 1024 * 1024
      )
        throw new Error('Web build exceeds bounds');
      // Fixed-size read also bounds memory if a local file grows after stat.
      const bytes = Buffer.alloc(stat.size + 1);
      const { bytesRead } = await handle.read(bytes, 0, bytes.length, 0);
      if (bytesRead !== stat.size)
        throw new Error('Web build changed during load');
      total += bytesRead;
      assets.set(path, { contentType, bytes: bytes.subarray(0, bytesRead) });
    } finally {
      await handle.close();
    }
  }
  await add('/', new URL('index.html', root), 'text/html; charset=utf-8');
  const names = await readdir(new URL('assets/', root));
  if (names.length > 100) throw new Error('Too many web assets');
  for (const name of names) {
    if (!/^[a-zA-Z0-9_-]+\.(js|css)$/.test(name))
      throw new Error('Unexpected web asset');
    await add(
      '/assets/' + name,
      new URL('assets/' + name, root),
      name.endsWith('.js') ? 'text/javascript' : 'text/css',
    );
  }
  return assets;
}
