export const pct = (v: number | null | undefined, digits = 0) => (v == null ? 'n/a' : `${(100 * v).toFixed(digits)}%`);
export const num = (v: number | null | undefined, digits = 1) => (v == null ? 'n/a' : v.toFixed(digits));
export const signed = (v: number | null | undefined, digits = 2) =>
  v == null ? 'n/a' : `${v > 0 ? '+' : v < 0 ? '−' : '±'}${Math.abs(v).toFixed(digits)}`;
export const day = (iso: string | null | undefined) => (iso ? iso.slice(0, 10) : 'not recorded');
