# field-test-controller

Local Field-Test Controller CLI (ADB/router sessions, scheduling, reports):

```text
src/cmd/b4-field-test
```

Build:

```sh
go -C src build -o ../out/b4-field-test ./cmd/b4-field-test
```

Router API is `/api/v1/test-sessions` and `/api/v1/capabilities`. This
controller must bind ADB on the Windows host; the router never executes ADB.
Verdicts come from `validation.ExecuteProfile` / `EvaluateHardGates`.
