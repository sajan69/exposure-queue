import assert from 'node:assert/strict';
import test from 'node:test';
import { createLocalServer } from '../src/http-server.js';
import { listenLocal } from '../src/listen-local.js';

test('startup binds numeric loopback and refuses invalid or occupied listeners', async () => {
  const server = createLocalServer(async () => ({ ok: true }));
  const other = createLocalServer(async () => ({}));
  for (const port of [-1, 65536, 1.5, NaN])
    await assert.rejects(listenLocal(server, port), RangeError);
  const port = await listenLocal(server, 0);
  try {
    assert.deepEqual(server.address(), {
      address: '127.0.0.1',
      family: 'IPv4',
      port,
    });
    await assert.rejects(listenLocal(server, 0), /already listening/);
    await assert.rejects(listenLocal(other, port), { code: 'EADDRINUSE' });
    assert.equal(
      other
        .listeners('listening')
        .some((listener) => listener.name === 'ready'),
      false,
    );
    assert.equal(
      other.listeners('error').some((listener) => listener.name === 'failed'),
      false,
    );
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});
