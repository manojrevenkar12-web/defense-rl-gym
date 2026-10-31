"""What the trained or graded side may read. The policy's observation is built only from visible
events; the patch sandbox gets requests, never the expected answers or the reference."""

import ast
from pathlib import Path

import drg

SRC = Path(drg.__file__).parent


def imports(path: Path) -> set[str]:
    out = set()
    for node in ast.walk(ast.parse(path.read_text())):
        if isinstance(node, ast.ImportFrom):
            out.add(("." * node.level) + (node.module or ""))
        elif isinstance(node, ast.Import):
            out |= {a.name for a in node.names}
    return out


def test_policy_and_features_do_not_use_truth():
    for f in [SRC / "rl" / "ppo.py", SRC / "soc" / "baselines.py"]:
        text = f.read_text()
        assert "truth" not in text and ".compromised" not in text and ".plan" not in text, f


def test_feature_function_reads_only_visible_events():
    src = (SRC / "soc" / "env.py").read_text()
    body = src[src.index("def host_features") : src.index("@dataclass\nclass FeatureEnv")]
    assert "sc.visible()" in body and "sc.events" not in body and "compromised" not in body and "plan" not in body


def test_the_sandbox_runner_imports_nothing_from_the_package():
    assert not any(m.startswith(("drg", ".")) for m in imports(SRC / "patch" / "runner.py"))
    assert not any(m.startswith(("drg", ".")) for m in imports(SRC / "patch" / "support.py"))


def test_sandbox_job_carries_no_expectations():
    src = (SRC / "patch" / "sandbox.py").read_text()
    assert 'json.dumps({"calls": calls, "world": world, "files": files})' in src
