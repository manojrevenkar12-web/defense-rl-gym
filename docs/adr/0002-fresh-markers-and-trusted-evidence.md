# 2. Fresh markers and evidence the service cannot reach

A hidden test that looks for a fixed secret in the response, or reads the service's own shell log,
can be passed by a patch that filters that secret or clears that log while staying exploitable.
The robust grader therefore (a) replaces every secret marker with a fresh random value on every
grading run, (b) takes the record of executed commands and writes from wrappers the runner
installs before the service is imported, not from state the service can touch, and (c) compares
legitimate responses with the reference fix's, so deleting the feature does not pass.
