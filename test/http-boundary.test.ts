import assert from 'node:assert/strict';
import test from 'node:test';
import { acceptsLocalRequest } from '../src/http-boundary.js';

test('local HTTP authority refuses rebinding hosts and cross-origin browser requests', () => {
  const authority = '127.0.0.1:4100';
  assert.equal(
    acceptsLocalRequest(authority, authority, undefined, undefined),
    true,
  );
  assert.equal(
    acceptsLocalRequest(
      authority,
      authority,
      `http://${authority}`,
      'same-origin',
    ),
    true,
  );
  for (const host of [
    undefined,
    'evil.example:4100',
    'localhost:4100',
    '127.0.0.1:4101',
  ]) {
    assert.equal(
      acceptsLocalRequest(authority, host, undefined, undefined),
      false,
    );
  }
  for (const origin of [
    'null',
    'https://evil.example',
    'http://localhost:4100',
  ]) {
    assert.equal(
      acceptsLocalRequest(authority, authority, origin, undefined),
      false,
    );
  }
  assert.equal(
    acceptsLocalRequest(authority, authority, undefined, 'cross-site'),
    false,
  );
  assert.equal(
    acceptsLocalRequest('0.0.0.0:4100', '0.0.0.0:4100', undefined, undefined),
    false,
  );
  assert.equal(
    acceptsLocalRequest(
      '127.0.0.1:65536',
      '127.0.0.1:65536',
      undefined,
      undefined,
    ),
    false,
  );
});
