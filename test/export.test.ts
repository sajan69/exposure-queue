import test from 'node:test';
import assert from 'node:assert/strict';
import { parse } from 'csv-parse/sync';
import { exportQueuePage } from '../src/export.js';

const row = {
  asset: 'host',
  cve: 'CVE-2024-1234',
  effective_status: 'open',
  kev_state: 'unavailable',
  epss_state: 'missing',
  epss: null,
};
test('CSV export preserves zero, missing evidence and quoted text', () => {
  const csv = exportQueuePage([
    { ...row, asset: 'a,"b\nline' },
    { ...row, epss_state: 'scored', epss: '0' },
  ]);
  const rows = parse(csv, { columns: true }) as Record<string, string>[];
  assert.equal(rows[0]!.asset, 'a,"b\nline');
  assert.equal(rows[0]!.epss, '');
  assert.equal(rows[0]!.epss_state, 'missing');
  assert.equal(rows[1]!.epss, '0');
});
test('CSV export neutralizes spreadsheet formulas and refuses oversized pages', () => {
  for (const asset of ['=1+1', '+cmd', '-1', '@SUM(A1)', '\t=1', '  =1']) {
    const [saved] = parse(exportQueuePage([{ ...row, asset }]), {
      columns: true,
    }) as Record<string, string>[];
    assert.equal(saved!.asset, `'${asset}`);
  }
  assert.throws(() => exportQueuePage(Array.from({ length: 101 }, () => row)));
});

test('CSV export refuses invalid or contradictory scores', () => {
  for (const epss of ['NaN', 'Infinity', '1.1', '-0.1', '=1', '0'.repeat(65)])
    assert.throws(() =>
      exportQueuePage([{ ...row, epss_state: 'scored', epss }]),
    );
  assert.throws(() => exportQueuePage([{ ...row, epss: '0' }]));
  assert.throws(() => exportQueuePage([{ ...row, epss_state: 'scored' }]));
});

test('CSV probability bounds use exact decimal value and refuse nonzero underflow', () => {
  for (const epss of [
    '1.0000000000000000001',
    '1e-9999',
    '10.000000000000000001e-1',
  ])
    assert.throws(() =>
      exportQueuePage([{ ...row, epss_state: 'scored', epss }]),
    );
  assert.match(
    exportQueuePage([{ ...row, epss_state: 'scored', epss: '5e-7' }]),
    /5e-7/,
  );
});

test('review export retains context, analyst evidence and feed identities', async () => {
  const { exportReviewPage } = await import('../src/export.js');
  const csv = exportReviewPage({
    revision: 7,
    asOf: '2026-11-17',
    filters: { minEpss: 0, kevState: 'unavailable', maxAgeDays: 2 },
    rows: [
      {
        ...row,
        analyst_decision: {
          owner: '=analyst',
          evidence: 'Reviewed,"quoted"\ncontext',
          reviewedOn: '2026-11-16',
          exceptionUntil: null,
        },
        kev_hash: 'a'.repeat(64),
        epss_hash: null,
        kev_published_on: '2026-11-15',
        epss_published_on: null,
      },
    ],
  });
  const [saved] = parse(csv, { columns: true }) as Record<string, string>[];
  assert.equal(saved!.revision, '7');
  assert.equal(saved!.as_of, '2026-11-17');
  assert.deepEqual(JSON.parse(saved!.filters_json!), {
    minEpss: 0,
    kevState: 'unavailable',
    maxAgeDays: 2,
  });
  assert.equal(saved!.owner, "'=analyst");
  assert.equal(saved!.evidence, 'Reviewed,"quoted"\ncontext');
  assert.equal(saved!.kev_hash, 'a'.repeat(64));
  assert.equal(saved!.epss_hash, '');
  assert.throws(() =>
    exportReviewPage({ revision: -1, asOf: 'bad', rows: [] }),
  );
});

test('review export preserves validated filter context', async () => {
  const { exportReviewPage } = await import('../src/export.js');
  assert.throws(() =>
    exportReviewPage({
      revision: 1,
      asOf: '2026-11-18',
      filters: { minEpss: 2 },
      rows: [],
    }),
  );
  assert.throws(() =>
    exportReviewPage({
      revision: 1,
      asOf: '2026-11-18',
      filters: { unknown: true },
      rows: [],
    }),
  );
});
