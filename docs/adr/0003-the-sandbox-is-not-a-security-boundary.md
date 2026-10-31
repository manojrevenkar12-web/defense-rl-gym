# 3. The sandbox is defence in depth, not a security boundary

Patches run in a subprocess started with `python -I -S`, resource limits (memory, CPU, file size,
wall clock), a clean environment, and an audit hook that refuses sockets, processes, native code,
frame inspection and writes outside a temporary root. A static policy rejects imports outside an
allow-list, dynamic code and any mutation of the support module.

This stops a policy from reaching the grader's state by accident or by simple tricks. It does not
contain a determined adversary: Python audit hooks can be bypassed. A training deployment runs
each grading job in a container with gVisor (or a VM), no network, and a read-only image.
