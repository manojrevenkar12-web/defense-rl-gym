# 5. Held-out sets are written blind and run once

The network family and the red-team patches are written by someone who has read only a writing
guide and what an agent sees. Each is run once; the first result is committed and never
rewritten (`tests/test_heldout_rule.py` checks the hashes and that a held-out set's grading has
not changed). A set whose failures are studied becomes a regression set and a new one is written.
