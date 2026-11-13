# ExposureQueue

ExposureQueue validates authorized asset/CVE findings CSV files and produces a
reviewable JSON preview without changing the input file. It identifies exact
normalized duplicates and blocks confirmation when records conflict or fail
validation. The current command is an offline ingestion component: it does not
write to PostgreSQL or provide a web service. Separate programming interfaces
provide findings imports and feed snapshot activation below.

## Run

Use Node.js 24 or 26 and npm. Dependencies are pinned in the lockfile.

```sh
npm ci
npm run preview -- examples/findings.csv 2026-11-08
```

The [synthetic example](examples/findings.csv) contains three records, two
distinct findings and one exact duplicate. Output includes the original byte
SHA-256, normalized findings, duplicate record numbers, validation issues and
`canConfirm`. Exit status is 2 for invalid input or a blocked preview. Review
output may contain asset identifiers; keep it within the authorized workspace.
No database writes occur.

## CSV contract

The required header order is:

```csv
asset,cve,observed_on,criticality,exposure
```

- Asset identifiers are case-sensitive ASCII identifiers of 1–128 characters,
  beginning with a letter or digit; subsequent characters may include
  `. _ : / -`.
- CVEs use `CVE-YYYY-NNNN` with 4–19 sequence digits. Lowercase input is
  uppercased; syntax validation does not establish that a CVE exists or affects
  an asset.
- Dates are valid Gregorian `YYYY-MM-DD` values no later than the explicit
  review date supplied to the command.
- Criticality is `low`, `medium`, `high` or `critical`; exposure is `internal`,
  `internet` or `unknown`. All values have surrounding whitespace trimmed.
- UTF-8 with optional BOM, quoted CSV fields and CRLF are supported. Invalid
  UTF-8, extra/missing columns, blank records and malformed quotes are rejected.
- Limits are 1 MiB of input, 1,000 data records and 4,096 characters per CSV
  record. Limits reject input rather than silently truncating it.

The duplicate key is the exact normalized `(asset, cve)` pair. Identical records
are reported once with references to the first record. Differing dates or
context for the same pair are conflicts requiring review. Record numbers count
logical CSV records, including the header, rather than physical lines inside
quoted fields. Valid rows remain visible alongside issues, but any issue sets
`canConfirm=false`. This is a preview indicator, not a persistence authorization
token.

## Implementation and verification

[CSV Parse](https://csv.js.org/parse/options/) handles CSV quoting and record
structure. [Zod](https://zod.dev/) validates field shapes and dates. Both
packages use MIT licensing; TypeScript uses Apache-2.0. Domain code defines
normalization, identity and conflict behavior. No network requests occur during
preview.

```sh
npm test
npm run lint
npm run format:check
npm run links
```

Tests cover the checked example, identity collisions, conflicting duplicates,
invalid dates/enums/identifiers, malformed CSV, BOM/CRLF, UTF-8 and bounds. CI
runs the tests, TypeScript build, ESLint, Prettier and external documentation
links on Node.js 24 and 26. These are synthetic mechanical checks, not detection
accuracy, production capacity or evidence of real asset exposure. Analyst
decisions are not implemented in this component.

## PostgreSQL import service

`src/store.ts` exports `initialize(pool)`,
`reviewImport(pool, bytes, reviewDate)` and
`confirmImport(pool, bytes, reviewDate, reviewedHash, reviewedRevision)` for a
single trusted workspace. Supply a node-postgres `Pool` connected to a dedicated
PostgreSQL 18 database. Call `initialize` before use; it creates the component's
three tables. This is a programming interface, with no HTTP server or database
CLI.

Review returns the CSV preview plus the current workspace revision. Confirmation
reparses the original bounded bytes and compares the reviewed hash. A
transaction locks the singleton workspace row, checks the reviewed revision,
inserts new findings and an import record, then advances the revision. Any
existing finding with different date or context aborts the entire batch;
identical existing findings are retained. Review does not predict database
conflicts: confirmation can refuse a batch even when its CSV-only `canConfirm`
is true. Repeated successful imports record a new review with zero inserted
findings and advance the revision.

The `(asset, cve)` primary key uses case-sensitive `C` collation. Database
checks also enforce identifier and context constraints. All values use
parameterized queries. Import does not overwrite existing records. All
application writers must participate in workspace revision locking; direct SQL
changes bypass that protocol. The database contains asset context in plaintext
and requires normal local access controls and backups. These functions provide
no authentication or tenant isolation.

Use a fresh disposable database for the integration test:

```sh
TEST_DATABASE_URL=postgres://USER:PASSWORD@127.0.0.1:5432/DISPOSABLE_DB npm run test:db
```

The test refuses a missing URL. It verifies atomic rollback after a partial
insert, unique/check constraints, hash and revision refusal, duplicate
preservation and two simultaneous confirmations where one must receive
`StaleReview`. CI supplies an isolated PostgreSQL service. PostgreSQL tests are
separate from `npm test` and must be run explicitly; they are not silently
skipped when no database is present.

After a connection failure during commit, the outcome can be unknown. Inspect
the workspace revision and import records before retrying; there is no automatic
retry or exactly-once delivery guarantee. `initialize` creates this schema only
and is not a general migration manager. Feed ingestion and analyst decision
tables are not provided by this component.

## Offline evidence snapshots

`parseKev(bytes, asOf)` and `parseEpss(bytes, asOf)` in `src/feeds.ts` validate
explicitly supplied, decompressed UTF-8 bytes. They perform no download or
database write. Both return the original byte SHA-256/length, publication day,
source label, version and validated rows. Source labels describe the expected
format; they do not authenticate where supplied bytes came from. Retain
acquisition URL, retrieval time and compressed-file hash separately when
acquiring real feeds.

The KEV parser follows the
[official schema](https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities_schema.json)
reviewed on 9 November 2026. It checks declared count, unique CVE identifiers,
required text/date fields, optional ransomware/forensic-triage/CWE fields and
date consistency. Unknown fields are refused so schema changes require review.
Input is limited to 64 MiB, 10,000 KEV rows and 16,384 characters per text
field. This is an application subset with additional bounds, not a general JSON
Schema validator. It uses JavaScript JSON parsing; duplicate JSON property names
are not separately detected. Duplicate CVE rows are always refused.

The EPSS parser accepts the dated `#model_version:...,score_date:...` metadata
line (a publication date or validated UTC timestamp) and exact
`cve,epss,percentile` header described by
[FIRST's bulk data documentation](https://www.first.org/epss/data). It requires
canonical uppercase CVE keys, finite decimal/scientific values in `[0,1]`,
unique rows, valid publication/review dates and no future publication day.
Limits are 64 MiB, 1,000,000 data rows and 256 characters per CSV record.
Unsupported historic files without metadata, hexadecimal/nonfinite/underflowing
numbers or changed schemas are refused. Scores use JavaScript numbers; original
bytes retain the exact source representation. No compressed input is accepted by
these parsers. Byte limits are not exact RAM limits or an adversarial-parser
sandbox.

`joinEvidence(cves, kevSnapshotOrNull, epssSnapshotOrNull, asOf)` joins exact
CVE identifiers only. It distinguishes unavailable snapshots, KEV `not-listed`,
EPSS `missing` and a genuine zero score. Publication age is returned in whole
UTC days; there is no hidden freshness threshold or automatic risk
classification. A stale snapshot remains dated evidence and must not be
represented as current.

CISA's
[KEV data license](https://raw.githubusercontent.com/cisagov/kev-data/develop/LICENSE)
states CC0 1.0 for the database; linked third-party material has separate terms.
EPSS scores are provided by FIRST's EPSS SIG and Empirical Security. FIRST's
[FAQ](https://www.first.org/epss/faq) permits free CSV/API access and requests
attribution; this project does not relabel EPSS data as CC0 or grant rights to
training data. EPSS estimates exploitation probability and is not a complete
risk score. Neither a KEV match nor an EPSS score proves that a specific asset
is vulnerable. KEV due dates are source fields, not an automatically applicable
local obligation.

The six feed tests use synthetic records only and cover validation, exact joins,
missing/zero distinctions, dates and bounds. They do not demonstrate successful
acquisition of a complete official snapshot, detection accuracy or operational
prioritization quality. These parser functions perform no persistence or
refresh.

## Reproduce archived source ingestion

```sh
npm run build
mkdir -p artifacts
node scripts/acquire-feeds.mjs artifacts/official-archives 2026-11-09
```

This explicit command downloads two complete fixed archives: CISA's KEV mirror
at commit `e5b3a9b25050a8da26c96266c5bfe438ee0bdebc` and the 8 November 2026
EPSS archive at commit `a14602d91346f3875c90d027824578b6b7eecc1d`. It does not
fetch the latest feed or accept arbitrary URLs. Reviewed Git blob SHA-1
identities and exact original byte lengths must match before decompression or
parsing. SHA-256 hashes of original and decoded bytes, retrieval timestamps,
publication days, versions and complete validated row counts are recorded in
`summary.json`. Hashes provide byte identity, not a publisher signature or
independent proof of accuracy. HTTPS and the selected official repositories
establish the acquisition route. EPSS is attributed to FIRST's EPSS SIG and
Empirical Security.

Downloads use fixed HTTPS URLs, refuse redirects and credentials, have a
30-second request timeout, and enforce an 8 MiB declared/streamed transfer cap.
Node's gzip implementation checks integrity with a 64 MiB output cap; the
existing complete snapshot parsers then apply their schema and row bounds.
Limits are not a precise RAM ceiling. No rows are sampled, truncated, repaired
or skipped. Network, hash, gzip or schema failure refuses the run. A new
directory is required, including when a prior attempt failed; existing
destinations are never cleared or reused. Parent directories must be trusted.
Successful output retains raw archives and the decoded EPSS CSV with private
creation permissions; these are not committed. This is not a filesystem
durability or hostile-parent race guarantee.

CI runs this explicit acquisition separately from synthetic tests and retains
only the provenance summary for seven days. A passing archive job demonstrates
complete validation of these specific bytes, not detection accuracy, local asset
applicability or operational prioritization quality. No database refresh or
automatic daily feed synchronization occurs.

The checked [acquisition record](examples/feed-acquisition.json) was measured
locally on Node.js 24.22.1/Linux x64. It contains 1,769 KEV records published on
6 November 2026 and all 401,956 EPSS scores published on 8 November 2026. The
original KEV file is 1,832,349 bytes; EPSS is 2,818,450 gzip bytes and
12,228,073 decoded bytes. The record retains full hashes, timestamps and source
identities. These are dated archives, not a claim about today's catalog. The
EPSS source uses a UTC publication timestamp and scientific notation in some
percentiles; both are validated explicitly. CI compares source identities,
decoded hashes, publication metadata and complete row counts with this record;
retrieval times and environment versions naturally differ across runs.

## Transactional feed snapshots

Call `initialize(pool)` followed by `initializeFeeds(pool)` from
`src/feed-store.ts` against a dedicated PostgreSQL database. Initialization is
create-only: it supports the schema shown here, not migration of earlier working
branch schemas. Do not point integration tests at an existing user database.

`activateFeed(pool, source, decodedBytes, asOf, expectedHash, expectedRevision, provenance)`
accepts `cisa-kev` or `first-epss`. It reparses the complete decoded bytes using
the same bounded parsers and requires their SHA-256 to match the reviewed hash.
Obtain the current revision from `reviewImport` or the workspace row. Provenance
requires exactly `url` (HTTPS, no embedded credentials), `retrievedAt` (UTC
timestamp) and `archiveSha256` (64 lowercase hexadecimal characters). All
validation occurs before acquiring a database connection.

Provenance is a caller-supplied acquisition record. This function does not fetch
the URL, authenticate its publisher or recompute the compressed archive hash:
retain the acquisition output and verify its original archive separately. The
stored decoded hash binds the rows to the supplied decoded bytes. Scores and
source fields are stored as JSONB under exact, case-sensitive CVE keys.

One transaction locks the same singleton workspace revision used by findings
imports, inserts snapshot metadata and rows in batches of at most 1,000, updates
the active pointer, and advances the revision. Stale callers must review again.
Older publication days and differing bytes on the active publication day are
refused. Repeating identical bytes creates another snapshot and advances the
revision; this is not an idempotency or exactly-once API. Historical snapshots
remain stored; no retention deletion or secure erasure is provided.

Snapshot rows, provenance, active pointer and revision commit together. On a
connection failure during commit the outcome can be unknown; inspect the
revision and snapshots before retrying. All application writers must follow the
revision protocol. Direct SQL changes can bypass it. The composite foreign key
prevents an active source from referencing another source's snapshot.

PostgreSQL integration tests use synthetic feeds. They force a failure at row
1,001 after the first batch is inserted and assert that rows, pointer and
revision roll back; separate backend connections compete against one revision,
with one activation succeeding and one receiving `StaleReview`. These fixtures
verify transaction mechanics. The archive CI job separately revalidates the
pinned archive bytes, activates both complete feeds in a fresh PostgreSQL schema
and compares every stored CVE and evidence object with the parsed source in
2,000-row pages. It checks snapshot metadata, provenance, active sources and
revision as well. This is correctness verification, not production capacity.
Reproduce after acquisition with
`TEST_DATABASE_URL=... node scripts/verify-archive-store.mjs artifacts/official-archives`.
The script requires a disposable database and owns the fixed
`archive_store_verification` schema; an existing schema is refused and never
removed. A newly created schema is dropped on completion or failure. There is no
HTTP feed refresh, SQL queue interface or automatic feed synchronization in
these functions.

## Read a filtered queue

After initializing findings and feed tables, `readQueue(pool, request)` from
`src/queue.ts` returns `{ revision, rows, next }`. For example:

```js
const request = { asOf: '2026-11-09', limit: 25, kevState: 'listed' };
const first = await readQueue(pool, request);
const second = first.next
  ? await readQueue(pool, { ...request, after: first.next })
  : null;
```

`asOf` is an explicit valid date, not a historical database snapshot: the query
uses currently active feeds and refuses a date before either feed's publication
day. Optional filters combine with AND: `criticality`, `kevState` (`listed`,
`not-listed`, `unavailable`), `minEpss` (inclusive 0–1) and `maxAgeDays`
(inclusive integer 0–36,500). The age filter requires both active feeds to exist
and be within the bound. It does not require a matching CVE in either feed. An
EPSS threshold excludes missing/unavailable scores; zero remains data. Omitting
filters retains missing evidence and dated snapshots.

Rows include finding context, exact-CVE evidence states, EPSS as a decimal
string or null, publication days, whole-day ages, decoded source hashes and
stored acquisition provenance. KEV absence in an available catalog is
`not-listed`; unavailable catalogs and missing EPSS rows remain distinct.
Provenance retains the caller-recorded limitations described above.

Pages contain at most 100 rows (default 50), ordered by case-sensitive asset
then CVE in C collation. Each page uses one read-only repeatable-read
transaction. Pass `next` unchanged as `after`, preserving date and filters. A
changed workspace revision or filter raises `StaleReview`; restart from the
first page. Page size may change. Cursors are ordinary validated objects, not
signed authorization credentials. Direct SQL changes bypassing revision updates
invalidate this coordination contract. No transaction stays open between pages.

The PostgreSQL fixture checks exact matches and prefix near misses, missing
feeds and rows, genuine zero scores, inclusive age boundaries, pagination,
changed filters and stale revisions. These are synthetic correctness cases, not
prioritization accuracy or workload-capacity measurements. This interface
provides no HTTP endpoint, authentication or automatic risk ranking.
