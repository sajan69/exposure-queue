import { access, readFile, readdir } from 'node:fs/promises';
import { resolve, dirname } from 'node:path';
import { LinkChecker } from 'linkinator';
const documents = [
  'README.md',
  ...(await readdir('docs'))
    .filter((name) => name.endsWith('.md'))
    .map((name) => `docs/${name}`),
];
const links = [];
for (const document of documents) {
  const markdown = await readFile(document, 'utf8');
  for (const match of markdown.matchAll(/\[[^\]]*\]\(([^\s)]+)\)/g)) {
    const target = match[1];
    if (target.startsWith('https:')) links.push(target);
    else if (!target.startsWith('#')) {
      await access(resolve(dirname(document), target.split('#')[0]));
      console.log(`OK local ${document}: ${target}`);
    }
  }
}
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
