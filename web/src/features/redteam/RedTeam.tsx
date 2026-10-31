import type { Results } from '../../shared/lib/results';
import { GRADERS } from '../../shared/lib/results';
import { GRADER_LABEL } from '../../shared/theme/tokens';
import { ScrollRegion } from '../../shared/ui/Section';
import styles from './redteam.module.css';

const STATUS = { heldout: 'held-out', regression: 'regression set' } as Record<string, string>;

export function RedTeam({ sets }: { sets: NonNullable<Results['redteam']> }) {
  const names = Object.keys(sets);
  return (
    <ScrollRegion label="Blind red-team results">
      <table className={styles.table}>
        <caption className="visually-hidden">
          Genuine fixes and hacks accepted by each grader, per red-team set, at its first run
        </caption>
        <thead>
          <tr>
            <th scope="col">Grader</th>
            {names.map((n) => (
              <th scope="colgroup" colSpan={2} key={n}>
                {n.replace('redteam_', 'Set ')}{' '}
                <span className={styles.status}>({STATUS[sets[n]!.status] ?? sets[n]!.status})</span>
              </th>
            ))}
          </tr>
          <tr>
            <td />
            {names.flatMap((n) => [
              <th scope="col" key={`${n}-f`} className={styles.sub}>
                Genuine fixes paid
              </th>,
              <th scope="col" key={`${n}-h`} className={styles.sub}>
                Hacks paid
              </th>,
            ])}
          </tr>
        </thead>
        <tbody>
          {GRADERS.map((g) => (
            <tr key={g}>
              <th scope="row" data-robust={g === 'robust' || undefined}>
                {GRADER_LABEL[g].name}
              </th>
              {names.flatMap((n) => {
                const v = sets[n]![g];
                return [
                  <td key={`${n}-f`} data-kind={v.fixes_accepted < v.fixes ? 'withheld' : undefined}>
                    {v.fixes ? `${v.fixes_accepted} of ${v.fixes}` : 'none'}
                  </td>,
                  <td key={`${n}-h`} data-kind={v.hacks_accepted > 0 ? 'unearned' : undefined}>
                    {v.hacks ? `${v.hacks_accepted} of ${v.hacks}` : 'none written'}
                  </td>,
                ];
              })}
            </tr>
          ))}
        </tbody>
      </table>
    </ScrollRegion>
  );
}
