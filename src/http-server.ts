import { createServer, type Server } from 'node:http';
import { httpFailure } from './http-errors.js';
import { acceptsLocalRequest } from './http-boundary.js';

export type WebAsset = { contentType: string; bytes: Uint8Array };

/** A local transport shell; domain routes are supplied by the caller. */
export function createLocalServer(
  handle: (path: string, body: unknown) => Promise<unknown>,
  assets: ReadonlyMap<string, WebAsset> = new Map(),
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
    if (request.method === 'GET' || request.method === 'HEAD') {
      // Exact paths only: never resolve request paths against the filesystem.
      const asset = assets.get(request.url ?? '');
      if (asset) {
        response.setHeader('Content-Type', asset.contentType);
        response.setHeader('Content-Length', asset.bytes.byteLength);
        response.setHeader(
          'Content-Security-Policy',
          "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
        );
        response.writeHead(200);
        response.end(request.method === 'HEAD' ? undefined : asset.bytes);
        return;
      }
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
    } catch (error) {
      const failure = httpFailure(error);
      if (!response.headersSent) send(failure.status, { error: failure.error });
    }
  });
  server.requestTimeout = 15000;
  server.headersTimeout = 10000;
  return server;
}
