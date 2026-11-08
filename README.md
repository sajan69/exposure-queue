# ExposureQueue

ExposureQueue validates authorized asset/CVE findings CSV files and produces a
reviewable JSON preview without changing the input file. It identifies exact
normalized duplicates and blocks confirmation when records conflict or fail
validation. The current command is an offline ingestion component: it does not
persist findings, fetch vulnerability feeds or provide a web service.

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
accuracy, production capacity or evidence of real asset exposure. Feed evidence,
persistence and analyst decisions are not implemented in this component.
