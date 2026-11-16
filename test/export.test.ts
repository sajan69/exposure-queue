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
