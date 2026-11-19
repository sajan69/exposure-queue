import { createServer, type Server } from 'node:http';
import { acceptsLocalRequest } from './http-boundary.js';

/** A local transport shell; domain routes are supplied by the caller. */
export function createLocalServer(
  handle: (path: string, body: unknown) => Promise<unknown>,
): Server {
  const server = createServer(async (request, response) => {
    response.setHeader('Cache-Control', 'no-store');
    response.setHeader('X-Content-Type-Options', 'nosniff');
    response.setHeader('Content-Type', 'application/json; charset=utf-8');
    const send = (status: number, body: unknown) => {
      response.writeHead(status);
      response.end(JSON.stringify(body));
    };
    const address = server.address();
    if (!address || typeof address === 'string')
      return send(503, { error: 'Unavailable' });
    const site = request.headers['sec-fetch-site'];
    if (
      !acceptsLocalRequest(
        `127.0.0.1:${address.port}`,
        request.headers.host,
        request.headers.origin,
        typeof site === 'string' ? site : undefined,
      )
    ) {
      return send(403, { error: 'Forbidden' });
    }
    if (request.method !== 'POST') return send(405, { error: 'POST required' });
    if (request.headers['content-type'] !== 'application/json')
      return send(415, { error: 'JSON required' });
    try {
      const chunks: Buffer[] = [];
      let bytes = 0;
      for await (const chunk of request) {
        bytes += chunk.length;
        if (bytes > 2 * 1024 * 1024)
          return send(413, { error: 'Request too large' });
        chunks.push(Buffer.from(chunk));
      }
      let body: unknown;
      try {
        body = JSON.parse(
          new TextDecoder('utf-8', { fatal: true }).decode(
            Buffer.concat(chunks),
          ),
        );
      } catch {
        return send(400, { error: 'Invalid JSON' });
      }
      send(200, await handle(request.url ?? '', body));
    } catch {
      if (!response.headersSent) send(500, { error: 'Request failed' });
    }
  });
  server.requestTimeout = 15000;
  server.headersTimeout = 10000;
  return server;
}
