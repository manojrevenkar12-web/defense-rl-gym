import { motion, useReducedMotion } from 'motion/react';
import { pct } from '../../shared/lib/format';
import { GRADERS, type GraderSummary, type Grader, VALID, VARIANTS } from '../../shared/lib/results';
import { GRADER_LABEL, MOTION, VARIANT_LABEL } from '../../shared/theme/tokens';
import styles from './graders.module.css';

/** How wrong a cell is: share of reward paid that was not earned, or withheld that was. */
export function mistake(variant: (typeof VARIANTS)[number], accepted: number): { kind: 'unearned' | 'withheld' | 'right'; size: number } {
  if (VALID.has(variant)) return accepted < 1 ? { kind: 'withheld', size: 1 - accepted } : { kind: 'right', size: 0 };
  return accepted > 0 ? { kind: 'unearned', size: accepted } : { kind: 'right', size: 0 };
}

function Cell({ variant, rate, col }: { variant: (typeof VARIANTS)[number]; rate: number | undefined; col: number }) {
  const reduce = useReducedMotion();
  if (rate == null) return <td className={styles.na}>n/a</td>;
  const m = mistake(variant, rate);
  const strong = m.size >= 0.5;
  return (
    <motion.td
      className={styles.cell}
      data-kind={m.kind}
      data-strong={strong || undefined}
      style={{ ['--size' as string]: `${Math.round(m.size * 100)}%` }}
      initial={reduce ? false : { opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ duration: MOTION.base, delay: reduce ? 0 : col * MOTION.stagger * 3, ease: MOTION.ease }}
    >
      {pct(rate)}
    </motion.td>
  );
}

export function GraderMatrix({ study }: { study: Record<Grader, GraderSummary> }) {
  const rows = VARIANTS.filter((v) => study.robust.by_variant[v] != null);
  return (
    <table className={styles.matrix}>
      <caption className="visually-hidden">
        Share of each kind of patch that each grader pays for. Valid fixes should be paid every time; everything else never.
      </caption>
      <thead>
        <tr>
          <th scope="col" className={styles.corner}>
            Patch
          </th>
          {GRADERS.map((g) => (
            <th key={g} scope="col" data-robust={g === 'robust' || undefined}>
              <span className={styles.gname}>{GRADER_LABEL[g].name}</span>
              <span className={styles.gnote}>{GRADER_LABEL[g].note}</span>
            </th>
          ))}
        </tr>
      </thead>
      <tbody>
        {rows.map((v, i) => (
          <tr key={v} data-first-invalid={(!VALID.has(v) && VALID.has(rows[i - 1] ?? 'partial')) || undefined}>
            <th scope="row">
              {VARIANT_LABEL[v]}
              <span className={styles.should}>{VALID.has(v) ? 'should be paid' : 'should not be paid'}</span>
            </th>
            {GRADERS.map((g, col) => (
              <Cell key={g} variant={v} rate={study[g].by_variant[v]} col={col} />
            ))}
          </tr>
        ))}
      </tbody>
      <tfoot>
        <tr>
          <th scope="row">Invalid patches paid</th>
          {GRADERS.map((g) => (
            <td key={g} data-kind={study[g].invalid_accepted > 0 ? 'unearned' : 'right'} className={styles.total}>
              {pct(study[g].invalid_accepted)}
            </td>
          ))}
        </tr>
        <tr>
          <th scope="row">Valid fixes refused</th>
          {GRADERS.map((g) => (
            <td key={g} data-kind={study[g].valid_accepted < 1 ? 'withheld' : 'right'} className={styles.total}>
              {pct(1 - study[g].valid_accepted)}
            </td>
          ))}
        </tr>
      </tfoot>
    </table>
  );
}
