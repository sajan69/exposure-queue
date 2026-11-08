import { open } from 'node:fs/promises';
import { MAX_BYTES, previewFindings } from './findings.js';

try {
  const [path, asOf, ...extra] = process.argv.slice(2);
  if (!path || !asOf || extra.length)
    throw new Error('Usage: npm run preview -- FILE YYYY-MM-DD');
  const file = await open(path, 'r');
  let bytes: Buffer;
  try {
    if (!(await file.stat()).isFile())
      throw new Error('Input must be a regular file');
    // A bounded read also handles a regular file growing after stat.
    bytes = Buffer.alloc(MAX_BYTES + 1);
    let offset = 0;
    while (offset < bytes.length) {
      const read = await file.read(bytes, offset, bytes.length - offset, null);
      if (!read.bytesRead) break;
      offset += read.bytesRead;
    }
    bytes = bytes.subarray(0, offset);
  } finally {
    await file.close();
  }
  const preview = previewFindings(bytes, asOf);
  process.stdout.write(JSON.stringify(preview, null, 2) + '\n');
  if (!preview.canConfirm) process.exitCode = 2;
} catch (error) {
  // Do not echo paths or untrusted CSV content in diagnostics.
  process.stderr.write(
    error instanceof Error && error.name === 'ImportError'
      ? error.message + '\n'
      : 'Cannot preview input; check file and arguments.\n',
  );
  process.exitCode = 2;
}
