import test from 'node:test';
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
