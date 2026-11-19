import assert from 'node:assert/strict';
import test from 'node:test';
import { once } from 'node:events';
import { createLocalServer } from '../src/http-server.js';

test('real HTTP requests enforce origin, JSON, size and sanitized failures', async () => {
  let calls = 0;
  const server = createLocalServer(async (path, body) => {
    calls++;
    if (path === '/fail') throw new Error('private database detail');
    return { body };
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  try {
    const address = server.address();
    assert.ok(address && typeof address !== 'string');
    const url = `http://127.0.0.1:${address.port}`;
    const post = (
      body: string,
      headers = { 'content-type': 'application/json' },
      path = '/',
    ) => fetch(url + path, { method: 'POST', headers, body });
    assert.equal((await post('{"value":0}')).status, 200);
    assert.equal(
      (
        await post('{}', {
          'content-type': 'application/json',
          ...{ origin: 'https://evil.example' },
        })
      ).status,
      403,
    );
    assert.equal((await post('{')).status, 400);
    assert.equal(
      (await post('{}', { 'content-type': 'text/plain' })).status,
      415,
    );
    assert.equal((await fetch(url)).status, 405);
    assert.equal((await post('x'.repeat(2 * 1024 * 1024 + 1))).status, 413);
    const failure = await post('{}', undefined, '/fail');
    assert.equal(failure.status, 500);
    assert.deepEqual(await failure.json(), { error: 'Request failed' });
    assert.equal(calls, 2);
  } finally {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});
