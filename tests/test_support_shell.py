"""The simulated shell parses like sh, records instead of running, and run_args never parses."""

from drg.patch import support


def fresh():
    support.reset({})
    return support.shell


def test_separators_and_substitution_are_recorded():
    sh = fresh()
    sh.run("ping -c 1 example.org; id && whoami | cat\nuname")
    assert [w[0] for w in sh.log] == ["ping", "id", "whoami", "cat", "uname"]


def test_command_substitution_runs_but_not_in_single_quotes():
    sh = fresh()
    sh.run('ping -c 1 "$(id)"')
    assert ["id"] in sh.log
    sh = fresh()
    sh.run("ping -c 1 '$(id)'")
    assert sh.log == [["ping", "-c", "1", "$(id)"]]


def test_backticks_run():
    sh = fresh()
    sh.run("ping `hostname`")
    assert ["hostname"] in sh.log


def test_run_args_is_one_program_and_never_a_shell():
    sh = fresh()
    out = sh.run_args(["ping", "-c", "1", "a.example; id"])
    assert sh.log == [["ping", "-c", "1", "a.example; id"]]
    assert "reachable" in out


def test_options_are_read_like_the_real_tool():
    sh = fresh()
    assert "x.example" in sh.run_args(["ping", "--", "x.example"])
    assert sh.run_args(["ping", "-oProxyCommand=id"]).endswith("?: reachable")


def test_reset_clears_the_log_and_world():
    sh = fresh()
    sh.run("id")
    support.reset({"records": {"a": {}}})
    assert sh.log == [] and support.WORLD["records"] == {"a": {}} and support.WORLD["writes"] == []
