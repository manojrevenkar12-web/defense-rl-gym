// Theme constants used from TypeScript (charts, motion). Colours resolve CSS variables.

export const MOTION = {
  fast: 0.18,
  base: 0.32,
  stagger: 0.07,
  ease: [0.2, 0.9, 0.3, 1] as [number, number, number, number],
} as const;

export const CHART = {
  width: 520,
  height: 230,
  padLeft: 44,
  padRight: 132,
  padTop: 14,
  padBottom: 34,
  line: 2.5,
  dash: '5 4',
  tick: 4,
  barWidth: 180,
  barHeight: 12,
} as const;

export const GRADER_LABEL = {
  reference_match: { name: 'Looks like the reference', note: 'diff similarity to the human fix' },
  public_tests: { name: 'Report requests', note: 'the two requests in the report' },
  hidden_security: { name: 'Hidden attacks', note: 'attack requests only' },
  hidden_tests: { name: 'Hidden tests', note: 'attacks and legitimate requests' },
  robust: { name: 'Robust', note: 'hidden tests, fresh markers, trusted log, static policy' },
} as const;

export const VARIANT_LABEL = {
  ref: 'Reference fix',
  alt1: 'Valid fix, written differently',
  alt2: 'Another valid fix',
  partial: 'Partial fix, one bypass left',
  overblock: 'Over-blocking fix',
  first_site_only: 'Fixes one of two functions',
  hack_delete: 'Hack: remove the feature',
  hack_public: 'Hack: special-case the report',
  hack_tamper: 'Hack: hide the evidence',
} as const;

/** Hue = reward trained on, dash = trained from scratch. Baselines are grey. */
export const POLICY_STYLE: Record<string, { label: string; color: string; dashed: boolean }> = {
  naive_scratch: { label: 'Naive reward, from scratch', color: 'var(--unearned)', dashed: true },
  robust_scratch: { label: 'Robust reward, from scratch', color: 'var(--robust)', dashed: true },
  naive_clone: { label: 'Naive reward, from the cloned analyst', color: 'var(--unearned)', dashed: false },
  robust_clone: { label: 'Robust reward, from the cloned analyst', color: 'var(--robust)', dashed: false },
  cloned_analyst: { label: 'Cloned analyst, before RL', color: 'var(--baseline)', dashed: false },
  analyst: { label: 'Rule-based analyst (tuned)', color: 'var(--baseline)', dashed: false },
  isolate_all: { label: 'Isolate everything', color: 'var(--baseline)', dashed: false },
  do_nothing: { label: 'Do nothing', color: 'var(--baseline)', dashed: false },
};

export const FAMILY_LABEL: Record<string, string> = {
  'corp-small': 'Training network',
  'corp-medium': 'Larger network',
  'noisy-admins': 'Busy admins',
  heldout: 'Held-out (blind)',
};
