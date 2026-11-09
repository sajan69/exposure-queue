import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  parseKev,
  parseEpss,
  joinEvidence,
  FEED_MAX_BYTES,
} from '../src/feeds.js';
const row = {
  cveID: 'CVE-2024-1234',
  vendorProject: 'Synthetic',
  product: 'Fixture',
  vulnerabilityName: 'Synthetic only',
  dateAdded: '2026-11-01',
  shortDescription: 'Not an advisory',
  requiredAction: 'Fixture action',
  dueDate: '2026-11-15',
  forensicTriage: 'No',
};
const kevInput = (rows = [row], count = rows.length) =>
  Buffer.from(
    JSON.stringify({
      catalogVersion: 'fixture-v1',
      dateReleased: '2026-11-08T00:00:00.000Z',
      count,
      vulnerabilities: rows,
    }),
  );
const epssInput = (body = 'CVE-2024-1234,0,1') =>
  Buffer.from(
    '#model_version:v2026.06.15,score_date:2026-11-08\ncve,epss,percentile\n' +
      body +
      '\n',
  );
test('synthetic KEV preserves fields, identity and original byte hash', () => {
  const value = parseKev(kevInput(), '2026-11-09');
  assert.deepEqual(value.rows, [row]);
  assert.equal(value.publishedOn, '2026-11-08');
  assert.match(value.sha256, /^[a-f0-9]{64}$/);
  assert.notEqual(
    value.sha256,
    parseKev(Buffer.from(kevInput().toString() + ' '), '2026-11-09').sha256,
  );
});
test('KEV rejects wrong count, duplicate CVE rows, unknown fields and inconsistent dates', () => {
  for (const bytes of [
    kevInput([row], 2),
    kevInput([row, row]),
    kevInput([{ ...row, dateAdded: '2026-11-09' }]),
    kevInput([{ ...row, dueDate: '2026-02-30' }]),
    kevInput([{ ...row, forensicTriage: 'maybe' }]),
    Buffer.from(
      kevInput().toString().replace('"count":1', '"extra":1,"count":1'),
    ),
  ])
    assert.throws(() => parseKev(bytes, '2026-11-09'));
});
test('EPSS accepts zero and boundaries with dated model metadata', () => {
  const result = parseEpss(epssInput(), '2026-11-09');
  assert.equal(result.rows[0]?.epss, 0);
  assert.equal(result.rows[0]?.percentile, 1);
  assert.equal(result.version, 'v2026.06.15');
  assert.deepEqual(
    parseEpss(
      Buffer.from(epssInput().toString().replaceAll('\n', '\r\n')),
      '2026-11-09',
    ).rows,
    result.rows,
  );
});
test('EPSS rejects duplicates, nondecimal/nonfinite/out-of-range scores and malformed records', () => {
  for (const body of [
    'CVE-2024-1234,NaN,0',
    'CVE-2024-1234,1.01,0',
    'CVE-2024-1234,-1,0',
    'CVE-2024-1234,1e3,0',
    'CVE-2024-1234,1e-999,0',
    'CVE-2024-1234,0x1,0',
    'CVE-2024-1234,,0',
    'CVE-2024-1234,0,0,extra',
    'CVE-2024-1234,0,0\nCVE-2024-1234,0,0',
    'cve-2024-1234,0,0',
  ])
    assert.throws(() => parseEpss(epssInput(body), '2026-11-09'));
  assert.throws(() =>
    parseEpss(
      Buffer.from('cve,epss,percentile\nCVE-2024-1234,0,0'),
      '2026-11-09',
    ),
  );
});
test('future dates, invalid review dates, invalid UTF8 and oversized feeds refuse', () => {
  for (const parse of [parseKev, parseEpss]) {
    assert.throws(() => parse(Buffer.alloc(FEED_MAX_BYTES + 1), '2026-11-09'));
    assert.throws(() => parse(Buffer.from([255]), '2026-11-09'));
  }
  assert.throws(() => parseKev(kevInput(), '2026-11-07'));
  assert.throws(() => parseEpss(epssInput(), '2026-11-07'));
  assert.throws(() => parseEpss(epssInput(), '2026-02-30'));
});
test('exact join distinguishes absent evidence, missing score, zero score and prefix near-miss', () => {
  const ids = ['CVE-2024-1234', 'CVE-2024-12340'];
  const k = parseKev(kevInput(), '2026-11-09');
  const e = parseEpss(epssInput(), '2026-11-09');
  const rows = joinEvidence(ids, k, e, '2026-11-09');
  assert.deepEqual(
    rows.map((r) => [
      r.kevState,
      r.epssState,
      r.epss?.epss ?? null,
      r.epssAgeDays,
    ]),
    [
      ['listed', 'scored', 0, 1],
      ['not-listed', 'missing', null, 1],
    ],
  );
  assert.equal(
    joinEvidence(ids, null, null, '2026-11-09')[0]?.epssState,
    'unavailable',
  );
  assert.throws(() => joinEvidence(['cve-2024-1234'], k, e, '2026-11-09'));
});

test('EPSS official UTC timestamp is validated and preserved without losing publication day', () => {
  const timestamp = '2026-11-08T12:00:26Z';
  const bytes = Buffer.from(
    epssInput()
      .toString()
      .replace('score_date:2026-11-08', 'score_date:' + timestamp),
  );
  const snapshot = parseEpss(bytes, '2026-11-09');
  assert.equal(snapshot.publishedAt, timestamp);
  assert.equal(snapshot.publishedOn, '2026-11-08');
  for (const bad of [
    '2026-11-08T25:00:00Z',
    '2026-02-30T12:00:00Z',
    '2026-11-08T12:00:00',
    '2026-11-08T12:00:00+05:00',
    '2026-11-10T00:00:00Z',
  ])
    assert.throws(() =>
      parseEpss(
        Buffer.from(bytes.toString().replace(timestamp, bad)),
        '2026-11-09',
      ),
    );
});

test('EPSS official scientific notation is finite, bounded and preserves zero distinction', () => {
  const snapshot = parseEpss(
    epssInput('CVE-2023-20914,0.0006,5e-05'),
    '2026-11-09',
  );
  assert.deepEqual(snapshot.rows[0], {
    cve: 'CVE-2023-20914',
    epss: 0.0006,
    percentile: 0.00005,
  });
  assert.equal(
    parseEpss(epssInput('CVE-2024-1234,1e+0,0e-05'), '2026-11-09').rows[0]
      ?.epss,
    1,
  );
});
