import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { MAX_BYTES, HEADERS, previewFindings } from '../src/findings.js';
const header = HEADERS.join(',') + '\n';
const row = 'web-01,CVE-2021-44228,2026-11-01,critical,internet';
const preview = (body: string) =>
  previewFindings(Buffer.from(header + body), '2026-11-08');
test('checked example normalizes CVE and reports duplicate without losing provenance', () => {
  const result = previewFindings(
    readFileSync('examples/findings.csv'),
    '2026-11-08',
  );
  assert.equal(result.canConfirm, true);
  assert.equal(result.inputRows, 3);
  assert.equal(result.findings.length, 2);
  assert.deepEqual(result.duplicates, [{ row: 4, firstRow: 2 }]);
  assert.match(result.sha256, /^[a-f0-9]{64}$/);
});
test('conflicting duplicate blocks the entire preview', () => {
  const result = preview(row + '\n' + row.replace('critical', 'low'));
  assert.equal(result.canConfirm, false);
  assert.deepEqual(result.issues, [
    { row: 3, field: 'asset,cve', code: 'conflicting_duplicate' },
  ]);
});
test('case-sensitive assets and exact CVE keys stay distinct', () => {
  const result = preview(
    [row, row.replace('web', 'WEB'), row.replace('44228', '442280')].join('\n'),
  );
  assert.equal(result.findings.length, 3);
  assert.equal(result.duplicates.length, 0);
});
test('strict dates, future dates, enums, IDs and CVEs reject invalid records', () => {
  for (const bad of [
    row.replace('11-01', '02-30'),
    row.replace('11-01', '11-09'),
    row.replace('critical', 'urgent'),
    row.replace('web-01', '=cmd'),
    row.replace('44228', '123'),
    row.replace('internet', 'yes'),
  ]) {
    assert.equal(preview(bad).canConfirm, false, bad);
  }
});
test('invalid rows do not erase valid records but prevent confirmation', () => {
  const result = preview(row + '\n' + row.replace('internet', 'invalid'));
  assert.equal(result.findings.length, 1);
  assert.equal(result.canConfirm, false);
  assert.equal(result.issues[0]?.row, 3);
});
test('BOM, CRLF and quoted cells parse; whitespace normalization is explicit', () => {
  const result = previewFindings(
    Buffer.from(
      '\ufeff' +
        header.replace('\n', '\r\n') +
        row.replace('web-01', '" web-01 "') +
        '\r\n',
    ),
    '2026-11-08',
  );
  assert.equal(result.findings[0]?.asset, 'web-01');
});
test('headers, extra columns, malformed quoting and empty data fail closed', () => {
  for (const input of [
    header,
    header.replace('asset', 'ASSET') + row,
    header + row + ',extra',
    header + '"unterminated',
    header + row + '\n\n',
  ]) {
    assert.throws(() => previewFindings(Buffer.from(input), '2026-11-08'));
  }
});
test('byte, record, row and UTF-8 limits reject rather than truncate', () => {
  assert.throws(() =>
    previewFindings(Buffer.alloc(MAX_BYTES + 1), '2026-11-08'),
  );
  assert.throws(() => previewFindings(new Uint8Array([255]), '2026-11-08'));
  assert.throws(() => preview('x'.repeat(4097)));
  assert.throws(() => preview(Array(1001).fill(row).join('\n')));
  assert.equal(
    preview(Array(1000).fill(row).join('\n')).duplicates.length,
    999,
  );
});
test('review date is caller supplied and validated; bytes determine digest', () => {
  assert.throws(() => previewFindings(Buffer.from(header + row), '2026-02-30'));
  assert.notEqual(preview(row).sha256, preview(row + '\n').sha256);
});
