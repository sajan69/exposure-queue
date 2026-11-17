import { z } from 'zod';

function representableProbability(value: string): boolean {
  const number = Number(value);
  if (!Number.isFinite(number) || number < 0 || number > 1) return false;
  const [mantissa, exponent = '0'] = value.split('e-');
  const [whole, fraction = ''] = mantissa!.split('.');
  const coefficient = BigInt(whole! + fraction);
  if (coefficient === 0n) return true;
  if (number === 0) return false;
  const scale = fraction.length + Number(exponent);
  // Nonzero representable numbers cannot require an unbounded exponent here.
  if (scale > 400) return false;
  return coefficient <= 10n ** BigInt(scale);
}

const rowSchema = z
  .object({
    asset: z.string().max(128),
    cve: z.string().regex(/^CVE-[0-9]{4}-[0-9]{4,19}$/),
    effective_status: z.enum([
      'open',
      'investigating',
      'resolved',
      'exception',
    ]),
    epss: z
      .string()
      .max(64)
      .regex(/^(?:0(?:\.[0-9]+)?|1(?:\.0+)?|[0-9]+(?:\.[0-9]+)?e-[0-9]+)$/)
      .refine(representableProbability)
      .nullable(),
    kev_state: z.enum(['listed', 'not-listed', 'unavailable']),
    epss_state: z.enum(['scored', 'missing', 'unavailable']),
  })
  .refine((row) => (row.epss_state === 'scored') === (row.epss !== null), {
    message: 'Score must agree with evidence state',
  });

function cell(value: string | null): string {
  const text = value ?? '';
  // Quoting alone does not stop spreadsheet formula evaluation.
  const safe = /^[\s\u0000-\u001f]*[=+@-]/u.test(text) ? `'${text}` : text;
  return `"${safe.replaceAll('"', '""')}"`;
}

/** Exports one bounded queue page; callers must retain its revision/context. */
export function exportQueuePage(input: unknown): string {
  const rows = z.array(rowSchema).max(100).parse(input);
  const columns = [
    'asset',
    'cve',
    'effective_status',
    'kev_state',
    'epss_state',
    'epss',
  ] as const;
  return (
    [
      columns.map(cell).join(','),
      ...rows.map((row) => columns.map((key) => cell(row[key])).join(',')),
    ].join('\r\n') + '\r\n'
  );
}

/** Review details accompany a bounded page, not an entire workspace backup. */
export function exportReviewPage(input: unknown): string {
  const detail = z
    .object({
      revision: z.number().int().nonnegative(),
      asOf: z.iso.date(),
      rows: z
        .array(
          rowSchema.and(
            z.object({
              analyst_decision: z
                .object({
                  owner: z.string().max(128),
                  evidence: z.string().max(4096),
                  reviewedOn: z.iso.date(),
                  exceptionUntil: z.iso.date().nullable(),
                })
                .nullable(),
              kev_hash: z
                .string()
                .regex(/^[a-f0-9]{64}$/)
                .nullable(),
              epss_hash: z
                .string()
                .regex(/^[a-f0-9]{64}$/)
                .nullable(),
              kev_published_on: z.iso.date().nullable(),
              epss_published_on: z.iso.date().nullable(),
            }),
          ),
        )
        .max(100),
    })
    .parse(input);
  const header = [
    'revision',
    'as_of',
    'asset',
    'cve',
    'effective_status',
    'kev_state',
    'epss_state',
    'epss',
    'owner',
    'evidence',
    'reviewed_on',
    'exception_until',
    'kev_hash',
    'epss_hash',
    'kev_published_on',
    'epss_published_on',
  ];
  const rows = detail.rows.map((row) => [
    String(detail.revision),
    detail.asOf,
    row.asset,
    row.cve,
    row.effective_status,
    row.kev_state,
    row.epss_state,
    row.epss,
    row.analyst_decision?.owner ?? null,
    row.analyst_decision?.evidence ?? null,
    row.analyst_decision?.reviewedOn ?? null,
    row.analyst_decision?.exceptionUntil ?? null,
    row.kev_hash,
    row.epss_hash,
    row.kev_published_on,
    row.epss_published_on,
  ]);
  return (
    [header, ...rows].map((row) => row.map(cell).join(',')).join('\r\n') +
    '\r\n'
  );
}
