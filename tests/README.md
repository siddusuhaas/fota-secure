# tests

End-to-end integration tests: package a dummy firmware directory with
`packager`, feed it into the built `consumer` binary, assert exit codes
and installed contents for both positive and negative (tampered/corrupt)
cases. Added in Phase 3 of `docs/TASKS.md`.
