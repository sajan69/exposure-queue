import { Pool } from 'pg';
import { createApi } from './api.js';
import { createLocalServer } from './http-server.js';
import { listenLocal } from './listen-local.js';

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
  const server = createLocalServer(createApi(pool));
  try {
    // Refuse an uninitialized database without creating or upgrading schemas.
    await pool.query('SELECT revision FROM eq_workspace WHERE id=1');
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
