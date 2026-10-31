"""Runs a service on a batch of requests inside the sandbox process. Started by `sandbox.run`.

The request inputs come on stdin; the expected answers never enter this process. Before the
service is imported, the shell and the record writer are wrapped so that what they did is captured
in this function's closure, and an audit hook refuses network, processes, native code, frame
inspection, and writes outside the sandbox directory. This is defence in depth for an RL grader,
not a security boundary: production runs would add a container or gVisor (docs/adr/0003).
"""

import json
import os
import signal
import sys


def main() -> None:
    work = sys.argv[1]
    job = json.loads(sys.stdin.read())
    root = os.environ["DRG_ROOT"]
    for rel, text in job.get("files", {}).items():
        path = os.path.join(root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write(text)
    sys.path.insert(0, work)
    import support

    executed: list = []
    written: list = []
    real_exec = support.Shell._exec
    real_save = support.save_record

    def exec_capture(self, words):
        executed.append(list(words))
        return real_exec(self, words)

    def save_capture(name, key, value):
        written.append({"collection": name, "key": key, "value": value})
        return real_save(name, key, value)

    support.Shell._exec = exec_capture
    support.save_record = save_capture

    blocked = ("socket.", "subprocess.", "os.system", "os.exec", "os.spawn", "os.posix_spawn", "os.fork", "os.kill",
               "ctypes.", "gc.get_referrers", "gc.get_objects", "sys.settrace", "sys.setprofile",
               "os.remove", "os.rename", "os.rmdir", "shutil.")
    real_root = os.path.realpath(root)

    def audit(event, args):
        if event.startswith(blocked) or event == "sys._getframe":
            raise PermissionError(f"sandbox: {event} is not allowed")
        if event == "open" and len(args) >= 2 and args[1] and any(c in str(args[1]) for c in "wax+"):
            target = os.path.realpath(str(args[0]))
            if not target.startswith(real_root + os.sep):
                raise PermissionError("sandbox: writes outside the sandbox are not allowed")

    sys.addaudithook(audit)

    def on_alarm(signum, frame):
        raise TimeoutError("request took too long")

    signal.signal(signal.SIGALRM, on_alarm)
    results = []
    try:
        import service
    except BaseException as e:  # noqa: BLE001 - an import failure is a result, not a crash
        print(json.dumps({"import_error": f"{type(e).__name__}: {e}"}))
        return
    for call in job["calls"]:
        support.reset(job["world"])
        executed.clear()
        written.clear()
        signal.alarm(2)
        try:
            args = {k: (v.replace("{root}", root) if isinstance(v, str) else v) for k, v in call["args"].items()}
            resp = service.handle({"op": call["op"], **args})
            if not isinstance(resp, dict):
                resp = {"status": 500, "body": "non-dict response"}
            resp = {"status": resp.get("status", 0), "body": str(resp.get("body", ""))[:20000], "headers": dict(resp.get("headers") or {})}
        except BaseException as e:  # noqa: BLE001
            resp = {"status": 599, "body": f"{type(e).__name__}"}
        finally:
            signal.alarm(0)
        results.append({"resp": resp, "shell": list(executed), "writes": list(written), "support_log": list(support.shell.log)})
    print(json.dumps({"results": results}))


if __name__ == "__main__":
    main()
