# Working on defense-rl-gym

## Fast feedback

- `pytest -q -m "not slow"`: support shell, every grader on every labelled patch kind, sandbox,
  incident world and rewards, PPO, harness, server, isolation and held-out checks (about 90 s).
- `pytest -q -m slow`: the whole pipeline on the quick profile (what CI runs end to end).
- `ruff check src tests scripts && ruff format --check src tests scripts`.
- `cd web && npm test && npm run lint && npm run build && npm run e2e` for the dashboard.
- `drg all --profile full` rebuilds the committed results (about 40 minutes on two cores) and ends
  with the release gate; `drg <step> --profile full` runs one step.

## Invariants (each has a test)

1. **Defensive only.** Services, attacks and the shell are simulated: `support.Shell` records a
   command line and runs nothing; attack strings are textbook test inputs; the incident world is
   generated. Do not add real exploit code, real network access or real command execution.
2. **The trained side never sees the truth.** The policy's features come from visible events only
   (`host_features` reads `sc.visible()`), baselines and PPO never read `compromised`, `plan` or
   `truth()` (`tests/test_isolation.py`). The patch sandbox receives requests, never expected
   answers, the reference fix or probe judgements (`sandbox.run`).
3. **A grader is trusted only after it is measured.** Any change to `patch/grader.py`, `cwe.py`
   or `runner.py` reruns `drg study` and the robust grader must still accept every valid patch
   and no invalid one (`tests/test_graders.py`, release floors). A new weakness class comes with
   ref/alt1/alt2/partial/overblock variants and probes.
4. **Settings live in `config/`** (sandbox limits, allow-lists, rewards, families, PPO, gate), not
   in code.
5. **Reports are generated.** `reports/results.json`, `reports/heldout/*` and `docs/REPORT.md`
   are written by `drg report`; never edit them by hand.

## The held-out rule

Held-out sets are written blind and run once:

- `heldout/heldout.yaml` (a network family) was written from `heldout/WRITING_FAMILY.md` by
  someone who had not seen the code; its hash is in `heldout/heldout.sha256` and its first run in
  `reports/heldout/first_run.json`. RL never trains or tunes on it.
- `heldout/redteam_vN/` are blind red-team patches written from `WRITING_PATCHES.md` against the
  task folders only. Each set's first grading is `reports/heldout/<set>_first_run.json`.

Never change a grader, a task generator, a reward or a policy to do better on a held-out set.
First runs are never rewritten. If you study a set's failures, write `regression` (and why) to
its `STATUS`, keep it as a regression set, and have someone who has not seen the code write a new
set from the writing guide only. `redteam_v1` went through exactly this (see its `STATUS`).

## Where things are

- `src/drg/patch/`: weakness generators (`cwe.py`), tasks (`task.py`), the sandbox (`runner.py`,
  `sandbox.py`, `support.py`), the five graders (`grader.py`), the agent environment (`env.py`).
- `src/drg/soc/`: the company world and intrusion (`world.py`), tool and feature views (`env.py`),
  rewards (`reward.py`), baselines.
- `src/drg/rl/ppo.py`: the policy, behaviour cloning and PPO.
- `src/drg/evaluate/`: grader study, red-team grading, RL study, held-out run, bench, report, gate.
- `src/drg/harness/`: tool-calling loop (Claude or replay) and transcripts; `src/drg/server/`: HTTP.
- `web/`: the dashboard over `reports/results.json`.
