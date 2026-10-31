import pytest

from drg.patch.cwe import CLASSES

CWES = sorted(CLASSES)


def pytest_collection_modifyitems(config, items):
    if config.getoption("-m"):
        return
    # nothing to do: `slow` tests run unless deselected with -m "not slow"


@pytest.fixture(scope="session")
def tasks():
    """One generated task per weakness class, with one and with two vulnerable functions."""
    from drg.patch.task import make_task

    out = {}
    for cwe in CWES:
        for seed in range(300, 400):
            t = make_task(seed, cwe)
            out.setdefault((cwe, t.two_sites), t)
            if (cwe, True) in out and (cwe, False) in out:
                break
    return out
