import { FeedError } from '../dist/src/feeds.js';
import { acquireArchives } from '../dist/src/acquire.js';
const [target, asOf, ...extra] = process.argv.slice(2);
if (!target || !asOf || extra.length) {
  console.error(
    'Usage: node scripts/acquire-feeds.mjs NEW_DIRECTORY YYYY-MM-DD',
  );
  process.exitCode = 2;
} else {
  try {
    const summary = await acquireArchives(target, asOf);
    console.log(JSON.stringify(summary));
  } catch (error) {
    console.error(
      error instanceof FeedError
        ? error.message
        : 'Archive transport or filesystem failure',
    );
    console.error(
      'Archive acquisition failed; partial destination is not reusable.',
    );
    process.exitCode = 2;
  }
}
