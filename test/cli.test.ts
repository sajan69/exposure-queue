import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';

test('installed build previews checked file without changing source', () => {
  const before = readFileSync('examples/findings.csv');
  const result = spawnSync(
    process.execPath,
    ['dist/src/cli.js', 'examples/findings.csv', '2026-11-08'],
    { encoding: 'utf8' },
  );
  assert.equal(result.status, 0);
  const output = JSON.parse(result.stdout) as {
    inputRows: number;
    canConfirm: boolean;
  };
  assert.equal(output.inputRows, 3);
  assert.equal(output.canConfirm, true);
  assert.deepEqual(readFileSync('examples/findings.csv'), before);
});
test('CLI blocks future observations and invalid input with exit status 2', () => {
  const result = spawnSync(
    process.execPath,
    ['dist/src/cli.js', 'examples/findings.csv', '2020-01-01'],
    { encoding: 'utf8' },
  );
  assert.equal(result.status, 2);
  assert.equal(
    (JSON.parse(result.stdout) as { canConfirm: boolean }).canConfirm,
    false,
  );
});
test('CLI sanitizes filesystem failures', () => {
  const result = spawnSync(
    process.execPath,
    ['dist/src/cli.js', 'private-nonexistent-path', '2026-11-08'],
    { encoding: 'utf8' },
  );
  assert.equal(result.status, 2);
  assert.equal(result.stdout, '');
  assert.doesNotMatch(result.stderr, /private-nonexistent-path|ENOENT|at /);
});
