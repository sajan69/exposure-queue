import type { Server } from 'node:http';

/** Bind only IPv4 loopback; port zero requests an OS-selected local port. */
export async function listenLocal(
  server: Server,
  port = 4100,
): Promise<number> {
  if (!Number.isInteger(port) || port < 0 || port > 65535) {
    throw new RangeError('Invalid local port');
  }
  if (server.listening) throw new Error('Server already listening');
  await new Promise<void>((resolve, reject) => {
    const failed = (error: Error) => {
      server.off('listening', ready);
      reject(error);
    };
    const ready = () => {
      server.off('error', failed);
      resolve();
    };
    server.once('error', failed);
    server.once('listening', ready);
    server.listen({ host: '127.0.0.1', port, exclusive: true });
  });
  const address = server.address();
  if (
    !address ||
    typeof address === 'string' ||
    address.address !== '127.0.0.1'
  ) {
    server.close();
    throw new Error('Unexpected listener address');
  }
  return address.port;
}
