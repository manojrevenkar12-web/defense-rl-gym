# 1. Measure the grader on patches whose validity is known

A reward for "fix this vulnerability" is a classifier over patches, and a policy will find its
false positives. So every task is generated together with patches whose validity is known by
construction (three valid fixes written differently; a partial fix; an over-blocking fix; a fix of
one of two vulnerable functions; three hacks), and every grader is scored on all of them before
it is used as a reward.

Consequence: the robust grader was designed knowing those hacks, which makes its generated-corpus
result circular. That is why a blind red team writes patches against the task folders alone, and
why that result is reported separately and kept as first recorded.
