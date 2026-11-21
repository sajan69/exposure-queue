# Local HTTP API

Build with `npm ci --ignore-scripts` and `npm run build`. Initialize the
database using the programmatic `initialize`, `initializeFeeds` and
`initializeTriage` functions described in the README. These create tables; they
are not migrations. Set `DATABASE_URL` in the process environment, then run:

```sh
node dist/src/serve.js
```

The entry point binds `127.0.0.1:4100`. It requires a reachable workspace table;
that startup check does not verify every table or repair incomplete schemas.
SIGINT and SIGTERM stop accepting requests and allow five seconds before open
HTTP connections are closed. Database connection errors print generic messages.

Every route accepts POST with exactly `Content-Type: application/json`. Requests
are bounded to 2 MiB, decoded as strict UTF-8 and parsed as JSON. Use the
numeric loopback URL: Host must match the listener's authority exactly. When
Origin is present it must match that HTTP origin. Cross-site Fetch Metadata is
refused. There is no CORS grant, authentication or protection against other
local processes. Operate this service only in one trusted local workspace; do
not expose it through a proxy or public network.

| Route                   | JSON input                                                      | Result                                        |
| ----------------------- | --------------------------------------------------------------- | --------------------------------------------- |
| `/api/import/review`    | `csv`, `asOf`                                                   | Preview, source SHA256 and workspace revision |
| `/api/import/confirm`   | Same original `csv`, `asOf`, `expectedHash`, `expectedRevision` | Inserted count and new revision               |
| `/api/queue`            | Queue request including date, filters and optional cursor       | Revision, rows and next cursor                |
| `/api/decision/save`    | Decision object described in README                             | New revision                                  |
| `/api/decision/read`    | `asset`, `cve`, `asOf`                                          | Saved decision and effective status, or null  |
| `/api/decision/history` | Identity, `throughRevision`, optional `afterRevision`, `limit`  | Bounded events and continuation               |
| `/api/export`           | `asOf` and optional queue filters                               | CSV string, revision and next cursor in JSON  |

Example queue request:

```sh
curl http://127.0.0.1:4100/api/queue \
  -H 'Content-Type: application/json' \
  --data '{"asOf":"2026-11-09","limit":50}'
```

Import confirmation reparses the original CSV and checks the hash and revision.
Retain the original input when reviewing. A 409 means the review is stale or a
finding conflicts; obtain current state and review again. Do not automatically
retry writes after a lost response because the commit outcome may be unknown.

Known invalid inputs return 400, unknown routes 404, unsupported methods 405,
unsupported content types 415 and oversized bodies 413. Host/origin refusals
return 403. Unexpected failures return a generic 500 without input or database
error details. Some domain range failures currently use that generic response.

Export reads rows on the server and applies the CSV formula guard. It currently
returns only the first page of at most 50 rows; its next cursor cannot yet be
submitted to the export route. It is a JSON response containing CSV, not an
attachment download or workspace backup. Queue pagination remains available
through `/api/queue`. Empty exports contain only CSV headers.

The PostgreSQL integration fixture sends real HTTP requests through import,
queue, decision, history and CSV export operations using synthetic findings. It
checks stale writes and invalid request refusals. It does not demonstrate public
deployment readiness, browser compatibility or production capacity.
