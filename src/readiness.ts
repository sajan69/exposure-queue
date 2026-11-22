import type { Pool } from 'pg';

/** Check the required relations without creating or modifying a workspace. */
export async function checkReadiness(pool: Pool): Promise<void> {
  const result = await pool.query(`
    SELECT revision FROM eq_workspace WHERE id=1
      AND (SELECT count(*) FROM (
        VALUES (to_regclass('eq_imports')), (to_regclass('eq_findings')),
          (to_regclass('eq_feed_snapshots')), (to_regclass('eq_feed_rows')),
          (to_regclass('eq_feed_active')), (to_regclass('eq_decisions')),
          (to_regclass('eq_decision_events'))
      ) AS required(relation) WHERE relation IS NOT NULL)=7
  `);
  if (
    result.rows.length !== 1 ||
    !Number.isSafeInteger(result.rows[0].revision) ||
    result.rows[0].revision < 0
  )
    throw new Error('Workspace is not initialized');
}
