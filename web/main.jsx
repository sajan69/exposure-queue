import React, { useState } from 'react';
import { createRoot } from 'react-dom/client';
import './style.css';
async function post(path, body) {
  const response = await fetch('/api/' + path, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  const result = await response.json();
  if (!response.ok) throw new Error(result.error || 'Request failed');
  return result;
}
function App() {
  const [draft, setDraft] = useState(null);
  const [csv, setCsv] = useState('');
  const [asOf, setAsOf] = useState(new Date().toISOString().slice(0, 10));
  const [preview, setPreview] = useState(null);
  const [page, setPage] = useState(null);
  const [filters, setFilters] = useState({
    criticality: '',
    kevState: '',
    minEpss: '',
    maxAgeDays: '',
  });
  const queueFilters = Object.fromEntries(
    Object.entries(filters)
      .filter(([, value]) => value !== '')
      .map(([key, value]) => [
        key,
        key === 'minEpss' || key === 'maxAgeDays' ? Number(value) : value,
      ]),
  );
  function changeFilter(key, value) {
    setFilters({ ...filters, [key]: value });
    setPage(null);
  }

  const [message, setMessage] = useState('');
  const [busy, setBusy] = useState(false);
  async function run(action) {
    setBusy(true);
    setMessage('');
    try {
      await action();
    } catch (error) {
      setMessage(error.message);
    } finally {
      setBusy(false);
    }
  }
  return (
    <main>
      <header>
        <p>LOCAL WORKSPACE</p>
        <h1>ExposureQueue</h1>
        <p>
          Review authorized findings against dated evidence. EPSS is
          probability, not complete risk; KEV does not prove an asset is
          affected.
        </p>
      </header>
      <label>
        Review date
        <input
          type="date"
          value={asOf}
          disabled={busy}
          onChange={(e) => {
            setAsOf(e.target.value);
            setPreview(null);
            setPage(null);
          }}
        />
      </label>
      <section>
        <h2>Import findings</h2>
        <label>
          Findings CSV
          <textarea
            rows="8"
            value={csv}
            disabled={busy}
            onChange={(e) => {
              setCsv(e.target.value);
              setPreview(null);
            }}
          />
        </label>
        <button
          disabled={busy || !csv}
          onClick={() =>
            run(async () =>
              setPreview(await post('import/review', { csv, asOf })),
            )
          }
        >
          Review import
        </button>
        {preview && (
          <>
            <pre>{JSON.stringify(preview, null, 2)}</pre>
            <button
              disabled={busy || !preview.canConfirm}
              onClick={() =>
                run(async () => {
                  await post('import/confirm', {
                    csv,
                    asOf,
                    expectedHash: preview.sha256,
                    expectedRevision: preview.revision,
                  });
                  setPreview(null);
                  setPage(null);
                  setMessage('Import committed.');
                })
              }
            >
              Confirm reviewed import
            </button>
          </>
        )}
      </section>
      <section>
        <h2>Findings queue</h2>
        <fieldset disabled={busy}>
          <legend>Evidence filters</legend>
          <label>
            Asset criticality
            <select
              value={filters.criticality}
              onChange={(e) => changeFilter('criticality', e.target.value)}
            >
              <option value="">All criticalities</option>
              {['low', 'medium', 'high', 'critical'].map((value) => (
                <option key={value}>{value}</option>
              ))}
            </select>
          </label>
          <label>
            KEV state
            <select
              value={filters.kevState}
              onChange={(e) => changeFilter('kevState', e.target.value)}
            >
              <option value="">All KEV states</option>
              {['listed', 'not-listed', 'unavailable'].map((value) => (
                <option key={value}>{value}</option>
              ))}
            </select>
          </label>
          <label>
            Minimum EPSS
            <input
              type="number"
              min="0"
              max="1"
              step="any"
              value={filters.minEpss}
              onChange={(e) => changeFilter('minEpss', e.target.value)}
            />
          </label>
          <label>
            Maximum feed age in days
            <input
              type="number"
              min="0"
              max="36500"
              step="1"
              value={filters.maxAgeDays}
              onChange={(e) => changeFilter('maxAgeDays', e.target.value)}
            />
          </label>
          <p>
            Age filtering requires both feeds. Missing EPSS rows do not meet a
            minimum score, including zero.
          </p>
        </fieldset>
        <button
          disabled={busy}
          onClick={() =>
            run(async () =>
              setPage(await post('queue', { asOf, ...queueFilters })),
            )
          }
        >
          Refresh queue
        </button>
        <button
          disabled={busy}
          onClick={() =>
            run(async () => {
              const exported = await post('export', {
                asOf,
                ...queueFilters,
                limit: 100,
              });
              const url = URL.createObjectURL(
                new Blob([exported.csv], { type: 'text/csv;charset=utf-8' }),
              );
              try {
                const link = document.createElement('a');
                link.href = url;
                link.download = 'exposure-queue.csv';
                document.body.append(link);
                link.click();
                link.remove();
              } finally {
                setTimeout(() => URL.revokeObjectURL(url), 1000);
              }
              setMessage(
                exported.next
                  ? 'Downloaded first 100 matching findings; more findings remain.'
                  : 'Downloaded matching findings.',
              );
            })
          }
        >
          Download first 100 matches as CSV
        </button>
        <p>
          CSV includes current review details and evidence provenance. It is not
          a backup.
        </p>
        {page && (
          <>
            <p>Workspace revision {page.revision}</p>
            <div className="scroll">
              <table>
                <thead>
                  <tr>
                    {[
                      'Asset',
                      'CVE',
                      'Criticality',
                      'KEV',
                      'EPSS',
                      'Status',
                      'Review',
                    ].map((x) => (
                      <th key={x}>{x}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {page.rows.map((row) => (
                    <tr key={JSON.stringify([row.asset, row.cve])}>
                      <td>{row.asset}</td>
                      <td>{row.cve}</td>
                      <td>{row.criticality}</td>
                      <td>{row.kev_state}</td>
                      <td>{row.epss ?? row.epss_state}</td>
                      <td>{row.effective_status}</td>
                      <td>
                        <button
                          type="button"
                          disabled={busy || !!draft}
                          onClick={() =>
                            setDraft({
                              asset: row.asset,
                              cve: row.cve,
                              expectedRevision: page.revision,
                              owner: row.analyst_decision?.owner ?? '',
                              evidence: row.analyst_decision?.evidence ?? '',
                              status: row.analyst_decision?.status ?? 'open',
                              reviewedOn: asOf,
                              exceptionUntil:
                                row.analyst_decision?.exceptionUntil ?? '',
                            })
                          }
                        >
                          Review {row.asset} {row.cve}
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {page.rows.length === 0 && <p>No findings on this page.</p>}
            <button
              disabled={busy || !page.next}
              onClick={() =>
                run(async () =>
                  setPage(
                    await post('queue', {
                      asOf,
                      ...queueFilters,
                      after: page.next,
                    }),
                  ),
                )
              }
            >
              Next page
            </button>
          </>
        )}
      </section>
      {draft && (
        <section>
          <h2>
            Review {draft.asset} {draft.cve}
          </h2>
          <p>
            Based on workspace revision {draft.expectedRevision}. Failed saves
            preserve this draft. Refresh and reopen the review after a conflict.
          </p>
          <form
            onSubmit={(event) => {
              event.preventDefault();
              run(async () => {
                await post('decision/save', {
                  ...draft,
                  exceptionUntil:
                    draft.status === 'exception' ? draft.exceptionUntil : null,
                });
                setDraft(null);
                setPage(null);
                setPreview(null);
                setMessage(
                  'Review saved. Refresh the queue to see current details.',
                );
              });
            }}
          >
            <fieldset disabled={busy}>
              <label>
                Owner label
                <input
                  required
                  maxLength={128}
                  value={draft.owner}
                  onChange={(e) =>
                    setDraft({ ...draft, owner: e.target.value })
                  }
                />
              </label>
              <label>
                Review status
                <select
                  value={draft.status}
                  onChange={(e) =>
                    setDraft({ ...draft, status: e.target.value })
                  }
                >
                  {['open', 'investigating', 'resolved', 'exception'].map(
                    (value) => (
                      <option key={value}>{value}</option>
                    ),
                  )}
                </select>
              </label>
              <label>
                Evidence
                <textarea
                  required
                  aria-label="Evidence"
                  maxLength={4096}
                  value={draft.evidence}
                  onChange={(e) =>
                    setDraft({ ...draft, evidence: e.target.value })
                  }
                />
              </label>
              <label>
                Reviewed on
                <input
                  required
                  type="date"
                  value={draft.reviewedOn}
                  onChange={(e) =>
                    setDraft({ ...draft, reviewedOn: e.target.value })
                  }
                />
              </label>
              {draft.status === 'exception' && (
                <label>
                  Exception expiry
                  <input
                    required
                    type="date"
                    min={draft.reviewedOn}
                    value={draft.exceptionUntil}
                    onChange={(e) =>
                      setDraft({ ...draft, exceptionUntil: e.target.value })
                    }
                  />
                </label>
              )}
              <button type="submit">Save review</button>
              <button type="button" onClick={() => setDraft(null)}>
                Discard review draft
              </button>
            </fieldset>
          </form>
        </section>
      )}
      <p role="status">{busy ? 'Working…' : message}</p>
    </main>
  );
}
createRoot(document.getElementById('root')).render(<App />);
