import { readFile } from 'node:fs/promises';
import { parse } from 'csv-parse/sync';
import test from 'node:test';
import { chromium } from 'playwright';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { Pool } from 'pg';
import { initialize } from '../src/store.js';
import { initializeFeeds } from '../src/feed-store.js';
import { initializeTriage } from '../src/triage.js';

if (!process.env.TEST_DATABASE_URL)
  throw new Error('TEST_DATABASE_URL required');
test(
  'CLI starts against initialized PostgreSQL and shuts down on SIGTERM',
  { timeout: 20000 },
  async () => {
    const pool = new Pool({ connectionString: process.env.TEST_DATABASE_URL });
    const client = await pool.connect();
    let owned = false;
    let child: ReturnType<typeof spawn> | undefined;
    try {
      await client.query('CREATE SCHEMA cli_fixture');
      owned = true;
      await client.query('SET search_path TO cli_fixture');
      const scoped = { query: client.query.bind(client) } as unknown as Pool;
      await initialize(scoped);
      await initializeFeeds(scoped);
      await initializeTriage(scoped);
      const url = new URL(process.env.TEST_DATABASE_URL!);
      url.searchParams.set('options', '-c search_path=cli_fixture');
      child = spawn(process.execPath, ['dist/src/serve.js'], {
        env: { ...process.env, DATABASE_URL: url.toString() },
        stdio: ['ignore', 'pipe', 'pipe'],
      });
      const exited = once(child, 'exit');
      await new Promise<void>((resolve, reject) => {
        const deadline = setTimeout(
          () => reject(new Error('CLI startup timed out')),
          10000,
        );
        let output = '';
        child!.stdout!.on('data', (chunk: Buffer) => {
          output += chunk.toString();
          if (output.includes('http://127.0.0.1:4100')) {
            clearTimeout(deadline);
            resolve();
          }
        });
        child!.once('exit', () => {
          clearTimeout(deadline);
          reject(new Error('CLI exited before readiness'));
        });
      });
      const home = await fetch('http://127.0.0.1:4100/');
      assert.equal(home.status, 200);
      const html = await home.text();
      assert.match(html, /ExposureQueue/);
      const scripts = [...html.matchAll(/(?:src|href)="(\/assets\/[^" ]+)"/g)];
      assert.equal(scripts.length, 2);
      for (const match of scripts) {
        const asset = await fetch('http://127.0.0.1:4100' + match[1]);
        assert.equal(asset.status, 200);
        assert.ok((await asset.arrayBuffer()).byteLength > 0);
      }
      const response = await fetch('http://127.0.0.1:4100/api/queue', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ asOf: '2026-11-09' }),
      });
      assert.equal(response.status, 200);
      assert.deepEqual(
        ((await response.json()) as { rows: unknown[] }).rows,
        [],
      );
      const browser = await chromium.launch();
      try {
        const page = await browser.newPage();
        const errors: string[] = [];
        page.on('pageerror', (error) => errors.push(error.message));
        await page.goto('http://127.0.0.1:4100/');
        await page.getByLabel('Review date').fill('2026-11-09');
        await page
          .getByLabel('Findings CSV')
          .fill(
            'asset,cve,observed_on,criticality,exposure\nalpha,CVE-2024-1234,2026-11-08,high,internal\n',
          );
        await page
          .getByRole('button', { name: 'Review import', exact: true })
          .click();
        await page
          .getByRole('button', { name: 'Confirm reviewed import' })
          .click();
        await page
          .getByRole('status')
          .filter({ hasText: 'Import committed.' })
          .waitFor();
        await page.getByRole('button', { name: 'Refresh queue' }).click();
        await page.getByRole('cell', { name: 'alpha', exact: true }).waitFor();
        const refresh = page.getByRole('button', { name: 'Refresh queue' });
        const alpha = page.getByRole('cell', { name: 'alpha', exact: true });
        const empty = page.getByText('No findings on this page.', {
          exact: true,
        });
        await page.getByLabel('Asset criticality').selectOption('low');
        assert.equal(await alpha.count(), 0);
        await refresh.click();
        await empty.waitFor();
        await page.getByLabel('Asset criticality').selectOption('high');
        await refresh.click();
        await alpha.waitFor();
        await page.setViewportSize({ width: 375, height: 812 });
        await page.getByLabel('KEV state').selectOption('listed');
        await refresh.click();
        await empty.waitFor();
        await page.getByLabel('KEV state').selectOption('unavailable');
        await refresh.click();
        await alpha.waitFor();
        await page.getByLabel('Minimum EPSS').fill('0');
        await refresh.click();
        await empty.waitFor();
        await page.getByLabel('Minimum EPSS').fill('');
        await page.getByLabel('Maximum feed age in days').fill('0');
        await refresh.click();
        await empty.waitFor();
        await page.getByLabel('Maximum feed age in days').fill('');
        await refresh.click();
        await alpha.waitFor();
        const downloadReady = page.waitForEvent('download');
        await page
          .getByRole('button', { name: 'Download first 100 matches as CSV' })
          .click();
        const download = await downloadReady;
        assert.equal(download.suggestedFilename(), 'exposure-queue.csv');
        assert.equal(await download.failure(), null);
        const downloadedPath = await download.path();
        assert.ok(downloadedPath);
        const records = parse(await readFile(downloadedPath, 'utf8'), {
          columns: true,
        }) as Record<string, string>[];
        assert.equal(records.length, 1);
        assert.equal(records[0]!.asset, 'alpha');
        assert.equal(records[0]!.cve, 'CVE-2024-1234');
        assert.equal(records[0]!.revision, '1');
        assert.equal(records[0]!.as_of, '2026-11-09');
        assert.deepEqual(JSON.parse(records[0]!.filters_json!), {
          criticality: 'high',
          kevState: 'unavailable',
        });
        await page
          .getByRole('button', {
            name: 'Review alpha CVE-2024-1234',
            exact: true,
          })
          .click();
        await page.getByLabel('Owner label').fill('Local analyst');
        await page.getByLabel('Review status').selectOption('investigating');
        await page
          .getByLabel('Evidence', { exact: true })
          .fill('Checked authorized scanner output.');
        await page
          .getByRole('button', { name: 'Save review', exact: true })
          .click();
        await page
          .getByRole('status')
          .filter({ hasText: 'Review saved.' })
          .waitFor();
        await refresh.click();
        await page
          .getByRole('cell', { name: 'investigating', exact: true })
          .waitFor();
        const saved = await client.query('SELECT decision FROM eq_decisions');
        assert.equal(saved.rows.length, 1);
        assert.equal(saved.rows[0].decision.owner, 'Local analyst');
        assert.equal(
          saved.rows[0].decision.evidence,
          'Checked authorized scanner output.',
        );
        await page
          .getByRole('button', {
            name: 'Review alpha CVE-2024-1234',
            exact: true,
          })
          .click();
        await page
          .getByLabel('Evidence', { exact: true })
          .fill('Unsaved local investigation notes.');
        const competing = await fetch(
          'http://127.0.0.1:4100/api/decision/save',
          {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({
              asset: 'alpha',
              cve: 'CVE-2024-1234',
              expectedRevision: 2,
              owner: 'Other local analyst',
              status: 'resolved',
              evidence: 'Verified remediation.',
              reviewedOn: '2026-11-09',
              exceptionUntil: null,
            }),
          },
        );
        assert.equal(competing.status, 200);
        await page
          .getByRole('button', { name: 'Save review', exact: true })
          .click();
        await page
          .getByRole('status')
          .filter({
            hasText: 'Workspace changed or finding conflicts; review again',
          })
          .waitFor();
        assert.equal(
          await page.getByLabel('Evidence', { exact: true }).inputValue(),
          'Unsaved local investigation notes.',
        );
        assert.equal(
          await page.getByLabel('Owner label').inputValue(),
          'Local analyst',
        );
        const afterConflict = await client.query(
          'SELECT decision FROM eq_decisions',
        );
        assert.equal(
          afterConflict.rows[0].decision.owner,
          'Other local analyst',
        );
        assert.equal(afterConflict.rows[0].decision.status, 'resolved');
        assert.equal(
          (
            await client.query(
              'SELECT count(*)::int AS n FROM eq_decision_events',
            )
          ).rows[0].n,
          2,
        );
        assert.deepEqual(errors, []);
        assert.equal(
          (await client.query('SELECT count(*)::int AS n FROM eq_findings'))
            .rows[0].n,
          1,
        );
      } finally {
        await browser.close();
      }
      child.kill('SIGTERM');
      const [code, signal] = await exited;
      assert.equal(code, 0);
      assert.equal(signal, null);
    } finally {
      if (child && child.exitCode === null) child.kill('SIGKILL');
      if (owned) await client.query('DROP SCHEMA cli_fixture CASCADE');
      client.release();
      await pool.end();
    }
  },
);
