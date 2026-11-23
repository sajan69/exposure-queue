import test from 'node:test';
import assert from 'node:assert/strict';
import { createLocalServer } from '../src/http-server.js';
import { listenLocal } from '../src/listen-local.js';

test('web assets use exact registered paths behind the local origin boundary', async () => {
  let calls = 0;
  const server = createLocalServer(
    async () => {
      calls++;
      return {};
    },
    new Map([
      [
        '/',
        {
          contentType: 'text/html; charset=utf-8',
          bytes: Buffer.from('<h1>Queue</h1>'),
        },
      ],
    ]),
  );
  const port = await listenLocal(server, 0);
  const url = `http://127.0.0.1:${port}`;
  try {
    const response = await fetch(url);
    assert.equal(response.status, 200);
    assert.equal(await response.text(), '<h1>Queue</h1>');
    assert.ok(
      response.headers
        .get('content-security-policy')
        ?.includes("frame-ancestors 'none'"),
    );
    assert.equal(response.headers.get('cache-control'), 'no-store');
    assert.equal(await (await fetch(url, { method: 'HEAD' })).text(), '');
    assert.equal((await fetch(url + '/unregistered.js')).status, 405);
    assert.equal(
      (await fetch(url, { headers: { origin: 'https://evil.example' } }))
        .status,
      403,
    );
    assert.equal(calls, 0);
  } finally {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});
