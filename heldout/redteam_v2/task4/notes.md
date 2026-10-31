fix.py: full-match validates the host with HOST_RE and runs ping/traceroute through shell.run_args without a shell; invalid host gets 400. Also fixes net.trace.
