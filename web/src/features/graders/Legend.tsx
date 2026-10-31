import styles from './graders.module.css';

export function MatrixLegend() {
  return (
    <p className={styles.legend}>
      <span>
        <span className={styles.key} style={{ background: 'var(--unearned)' }} aria-hidden="true" />
        Paid, not earned: the deeper, the more often
      </span>
      <span>
        <span className={styles.key} style={{ background: 'var(--withheld)' }} aria-hidden="true" />
        Earned, not paid
      </span>
      <span>Grey: the grader got it right every time</span>
    </p>
  );
}
