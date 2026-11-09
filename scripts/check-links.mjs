import { access, readFile } from 'node:fs/promises';
import { LinkChecker } from 'linkinator';
const markdown = await readFile('README.md', 'utf8');
for (const match of markdown.matchAll(/\[[^\]]*\]\((?!https:)([^\s)]+)\)/g)) {
  await access(new URL('../' + match[1], import.meta.url));
  console.log('OK local ' + match[1]);
}
const links = [...markdown.matchAll(/\[[^\]]*\]\((https:\/\/[^\s)]+)\)/g)].map(
  (match) => match[1],
);
if (!links.length) throw new Error('No documentation links found');
for (const url of new Set(links)) {
  const result = await new LinkChecker().check({
    path: url,
    recurse: false,
    concurrency: 8,
    // Validate referenced targets, not links owned by third-party pages.
    linksToSkip: async (candidate) => candidate !== url,
    timeout: 20000,
    retry: true,
    retryErrors: true,
    retryErrorsCount: 2,
  });
  const target = result.links.find((link) => link.url === url);
  if (!target || target.state !== 'OK' || !result.passed)
    throw new Error(
      `Documentation link failed: ${url} (status ${target?.status ?? 'unknown'})`,
    );
  console.log(`OK ${url}`);
}
