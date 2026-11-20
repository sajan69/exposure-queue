import assert from 'node:assert/strict';
import test from 'node:test';
import { z } from 'zod';
import { httpFailure, RouteNotFound } from '../src/http-errors.js';
import { ImportError } from '../src/findings.js';
import { StaleReview, FindingConflict } from '../src/store.js';

test('HTTP errors classify known failures without reflecting sensitive messages', () => {
  const invalid = z.string().safeParse(0);
  assert.equal(invalid.success, false);
  if (!invalid.success) assert.equal(httpFailure(invalid.error).status, 400);
  assert.equal(httpFailure(new ImportError('private CSV')).status, 400);
  for (const error of [
    new StaleReview('private asset'),
    new FindingConflict('private finding'),
  ]) {
    assert.equal(httpFailure(error).status, 409);
    assert.equal(httpFailure(error).error.includes('private'), false);
  }
  assert.equal(httpFailure(new RouteNotFound()).status, 404);
  assert.deepEqual(httpFailure(new Error('database password')), {
    status: 500,
    error: 'Request failed',
  });
});
