import { useState } from 'react';
import { num, pct, signed } from '../../shared/lib/format';
import { boardFor, type Results } from '../../shared/lib/results';
import { FAMILY_LABEL, POLICY_STYLE } from '../../shared/theme/tokens';
import { ScrollRegion } from '../../shared/ui/Section';
import { Segmented } from '../../shared/ui/Segmented';
import { EmptyState } from '../../shared/ui/StateBlock';
import styles from './policies.module.css';

const TRAINED = new Set(['naive_scratch', 'robust_scratch', 'naive_clone', 'robust_clone', 'cloned_analyst']);

/** Reward as a bar from zero, scaled to the largest magnitude on the board. */
function RewardBar({ value, scale, color }: { value: number; scale: number; color: string }) {
  const w = scale > 0 ? (Math.abs(value) / scale) * 50 : 0;
  return (
    <span className={styles.bar} aria-hidden="true">
      <span className={styles.zero} />
      <span className={styles.fill} style={{ background: color, width: `${w}%`, left: value >= 0 ? '50%' : `${50 - w}%` }} />
    </span>
  );
}

export function PolicyBoard({ r }: { r: Results }) {
  const families = [...(r.rl?.families ?? []), ...(r.heldout ? ['heldout'] : [])];
  const [family, setFamily] = useState(families[0] ?? 'corp-small');
  const rows = boardFor(r, family);
  const scale = Math.max(0, ...rows.map((x) => Math.abs(x.ep.reward)));
  return (
    <div className={styles.board}>
      <Segmented label="Network" options={families} value={family} onChange={setFamily} format={(f) => FAMILY_LABEL[f] ?? f} />
      <p className={styles.note}>
        {family === 'heldout'
          ? `Written blind from a one-page brief and run once (${r.heldout?.recorded_at?.slice(0, 10) ?? 'date not recorded'}). Never rerun after changes.`
          : family === r.rl?.families[0]
            ? 'The network the policies trained on, with evaluation seeds they never saw.'
            : 'Never trained on: a different size or a different amount of routine admin noise.'}
      </p>
      {rows.length === 0 ? (
        <EmptyState title="No results for this network">This network was not evaluated in the committed run.</EmptyState>
      ) : (
        <ScrollRegion label={`Policies on the ${FAMILY_LABEL[family] ?? family}`}>
          <table className={styles.table}>
            <caption className="visually-hidden">Each policy judged by the robust reward and its parts</caption>
            <thead>
              <tr>
                <th scope="col">Policy</th>
                <th scope="col" className={styles.rewardHead}>
                  Robust reward
                </th>
                <th scope="col">Attack stopped</th>
                <th scope="col">Innocent machines cut off</th>
                <th scope="col">Attacker’s machines isolated</th>
              </tr>
            </thead>
            <tbody>
              {rows.map(({ key, ep }) => {
                const s = POLICY_STYLE[key] ?? { label: key, color: 'var(--baseline)', dashed: false };
                return (
                  <tr key={key} data-trained={TRAINED.has(key) || undefined}>
                    <th scope="row">
                      <span
                        className={styles.swatch}
                        data-dashed={s.dashed || undefined}
                        style={{ borderColor: s.color }}
                        aria-hidden="true"
                      />
                      {s.label}
                    </th>
                    <td className={styles.rewardCell}>
                      <span className={styles.reward}>
                        <span className={styles.value}>{signed(ep.reward)}</span>
                        <RewardBar value={ep.reward} scale={scale} color={s.color} />
                      </span>
                    </td>
                    <td>{pct(ep.contained)}</td>
                    <td data-bad={ep.benign_isolated >= 1 || undefined}>{num(ep.benign_isolated)}</td>
                    <td>{pct(ep.caught)}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </ScrollRegion>
      )}
    </div>
  );
}
