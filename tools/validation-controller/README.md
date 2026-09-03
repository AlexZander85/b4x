# validation-controller

Umbrella L0–L8 validation CLI lives in the Go module:

```text
src/cmd/b4-validate
```

Build:

```sh
go -C src build -o ../out/b4-validate ./cmd/b4-validate
```

This directory is not a second verdict store. All aggregation goes through
`github.com/daniellavrushin/b4/validation`.
