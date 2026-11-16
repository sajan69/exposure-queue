import { z } from 'zod';

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
      .refine(
        (value) =>
          Number.isFinite(Number(value)) &&
          Number(value) >= 0 &&
          Number(value) <= 1,
      )
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
