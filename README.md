# defense-rl-gym

Reinforcement-learning environments for defensive security, built so that the reward is measured
before anything is trained on it.

- **Patching.** A generated Python service has a reported weakness in one of six classes: SQL
  injection, path traversal, command injection, missing authorisation, cross-site scripting and
  open redirect. The agent reads the files, edits `service.py` and submits. Five graders decide
  whether the fix deserves reward, and each is scored first on patches whose validity is known by
  construction.
- **Incident response.** A generated company network goes about its normal work while an intrusion
  goes on in it. The agent searches the logs, inspects hosts, cuts machines off and reports. The
  attack keeps moving while the agent works.

Both environments run in-process, behind an HTTP server and through a tool-calling harness. The
harness uses Anthropic Messages API tool schemas and writes transcripts as JSONL.

Everything is simulated. The shell parses a command line the way `sh` would, records it and runs
nothing. The services, the network and the attacker are generated. No real system is touched.

## Results (committed full run, `docs/REPORT.md`)

**Which patching reward pays only for real fixes?** The study covers 240 generated tasks and 10,410
gradings:

| Grader | Valid fixes paid | Invalid patches paid |
|---|---:|---:|
| Looks like the reference fix | 48% | 26% |
| The report's two requests | 100% | 74% |
| Hidden attack requests only | 100% | 39% (removing the feature: 100%) |
| Hidden attacks and hidden legitimate requests | 100% | 6% (hiding the evidence: 33%) |
| **Robust**: the hidden tests, plus fresh secret markers per run, a command log the service cannot reach, and a static policy | **100%** | **0%** |

The robust grader was designed knowing these hacks, so that result is partly circular. The fairer
test is the blind red team:

- **Set 1:** 0 of 18 hacks paid and 5 of 6 genuine fixes paid, recorded at its first run. The one
  rejected fix exposed a gap in the task generator: the task never told the agent that
  administrators may read every record. The task text now states the access rule, and the set is
  kept as a regression set (`heldout/redteam_v1/STATUS`).
- **Set 2** was written after that change by a new writer, against the new task text: 6 of 6 genuine
  fixes paid. Its writer produced fixes only (see Limits).

**What does a learned policy do with each reward?** PPO on the incident environment, two seeds per
variant, judged on unseen seeds by the robust reward:

| Policy (training network) | Robust reward | Attack stopped | Innocent machines cut off |
|---|---:|---:|---:|
| Naive reward ("the data did not leave"), from scratch | −2.89 | 100% | 10.5 |
| Robust reward, from scratch | −0.04 | 0% | 0.0 |
| Naive reward, from a cloned analyst | −0.09 | 100% | 1.7 |
| **Robust reward, from a cloned analyst** | **+1.00** | 97% | 0.02 |
| Rule-based analyst, threshold tuned on training seeds | +0.85 | 94% | 0.3 |
| Isolate everything | −2.87 | 100% | 10.5 |

- From scratch, the naive reward is gamed exactly as expected: cut everyone off.
- From scratch, the robust reward teaches the policy to give up, because every early mistake costs
  more than doing nothing. Paying credit at the step that earned it (same return, tested) did not
  change that. Starting from behaviour cloning did.
- On networks it never trained on, the robust policy reaches +0.99 on a larger one (analyst +0.67)
  and +0.99 with busy admins (analyst +0.38).
- **Blind held-out network**, written from a one-page brief by someone who had not seen the code and
  run once: the robust policy scores **+0.96** against **+0.09** for the tuned analyst and −4.19
  for isolating everything.

Throughput on one core: 56 incident episodes per second, and 7 robust patch grades per second
(each grade also runs the reference fix).

## Limits

- **The red team is small:** six tasks and 18 hacks in set 1. Set 2 has fixes only: an automated
  safety check stopped the writing of its hack patches, and I did not work around it. So the
  "no hack paid" result rests on set 1 and on the generated corpus.
- **The sandbox is not a security boundary.** It uses `python -I -S`, resource limits, audit hooks
  and a static policy. Training would run each grading in gVisor or a VM with no network
  (`docs/adr/0003`).
- **Generated services are small,** one or two functions each, and the weakness classes are six
  textbook ones. Real repositories are larger, and their tests are weaker than these hidden tests.
- **The robust policy isolates fewer of the attacker's machines than the analyst** (70% against
  68–89%). The reward pays only 0.3 for that share, and the policy trades it for fewer innocent
  machines cut off. Whether that weight is right is a judgement for a security team, not something
  this study settles.
- **The analyst's tuned threshold (2.0) sits at the edge of the grid it was tuned over.** A wider
  grid could give a stronger baseline. The held-out comparison was run once and is not rerun.
- **Two seeds per variant.** The differences between variants are large, but the confidence on the
  smaller gaps (+0.15 over the analyst on the training network) is limited.
- **The policies here are small PPO networks over detector features, not language models.** The
  harness can run Claude on both environments; tests and CI use a replay model, so they are free
  and reproducible. No Claude results are reported.

## Run it

```bash
pip install torch --index-url https://download.pytorch.org/whl/cpu
pip install -e ".[rl,server,dev]"
pytest -m "not slow"            # about 90 s
drg all --profile quick         # the whole pipeline in a few minutes
drg all --profile full          # the committed run (about 40 minutes on two cores)
drg serve                       # environments over HTTP on :8080
cd web && npm ci && npm run dev # the dashboard over reports/results.json
```

The HTTP API:

- `POST /v1/episodes` with `{"env": "patch" | "soc", "seed": 1}` returns the first observation and
  the tool schemas.
- `POST /v1/episodes/{id}/step` with `{"tool": "...", "args": {...}}` returns the observation,
  the reward and whether the episode is done.
- `/healthz`, `/readyz` and `/metrics` (Prometheus).

## How it is built

- `src/drg/patch/`: weakness generators with labelled patch variants, the task workspace, the
  sandbox runner, the five graders and the agent environment.
- `src/drg/soc/`: the company world and intrusion plan, the tool and feature views, and the rewards.
- `src/drg/rl/ppo.py`: a permutation-equivariant host policy, behaviour cloning and PPO.
- `src/drg/evaluate/`: the grader study, red-team grading, the RL study, the held-out run, the
  benchmark, the report and the release gate.
- `heldout/`: blind sets and their writing guides. First runs are in `reports/heldout/` and are
  never rewritten (`AGENTS.md`).
- `web/`: React and Motion dashboard (loading, error and empty states; Vitest, Playwright and axe).
- `docs/adr/`: why the grader is measured, fresh markers, the sandbox, reward design, and the
  held-out sets.

CI runs four jobs: lint and tests with the release gate on the committed run; the quick pipeline;
the server image run read-only and smoke-tested over HTTP; and the dashboard.

Built by Manoj Kumar Prakash with Claude Code (Anthropic). Claude wrote most of the code under my
direction. The blind held-out sets were written by separate Claude subagents that saw only the
writing guides and the task folders.
