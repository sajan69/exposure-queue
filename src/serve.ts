import { readdir, readFile } from 'node:fs/promises';
import { Pool } from 'pg';
import { createApi } from './api.js';
import { createLocalServer } from './http-server.js';
import { listenLocal } from './listen-local.js';
import { checkReadiness } from './readiness.js';

const connectionString = process.env.DATABASE_URL;
if (!connectionString) {
  console.error('DATABASE_URL is required');
  process.exitCode = 2;
} else {
  const pool = new Pool({
    connectionString,
    max: 4,
    connectionTimeoutMillis: 5000,
  });
  pool.on('error', () => {
    console.error('Database connection failed');
  });
  const assets = new Map();
  const root = new URL('../web/', import.meta.url);
  assets.set('/', {
    contentType: 'text/html; charset=utf-8',
    bytes: await readFile(new URL('index.html', root)),
  });
  for (const name of await readdir(new URL('assets/', root))) {
    if (!/^[a-zA-Z0-9_-]+\.(js|css)$/.test(name))
      throw new Error('Unexpected web asset');
    assets.set('/assets/' + name, {
      contentType: name.endsWith('.js') ? 'text/javascript' : 'text/css',
      bytes: await readFile(new URL('assets/' + name, root)),
    });
  }
  const server = createLocalServer(createApi(pool), assets);
  try {
    // Refuse an uninitialized database without creating or upgrading schemas.
    await checkReadiness(pool);
    const port = await listenLocal(server);
    console.log(`ExposureQueue API listening on http://127.0.0.1:${port}`);
    let closing = false;
    const shutdown = () => {
      if (closing) return;
      closing = true;
      server.close(() => {
        void pool.end();
      });
      const deadline = setTimeout(() => {
        server.closeAllConnections();
      }, 5000);
      deadline.unref();
    };
    process.once('SIGINT', shutdown);
    process.once('SIGTERM', shutdown);
  } catch {
    console.error(
      'Unable to start API; check database initialization and local port',
    );
    await pool.end();
    process.exitCode = 2;
  }
}
