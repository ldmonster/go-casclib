# casclib-parity-c

C++ implementation of the go-casclib parity contract, linked against the
vendored upstream [CascLib](../../CascLib). Used as the **parity oracle**:
the same JSONL test scenarios run by `tools/parity` are driven against
both this binary and `bin/casc-parity`, and the diff is the source of
truth for behavioral parity.

## Build

```bash
cd tools/casclib-parity-c
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
# binary: build/casclib-parity-c
```

## Protocol (v0.1.0)

Identical to `casc-parity`. See [tools/paritycmd/main.go](../paritycmd/main.go)
for the canonical reference; the four subcommands are
`capabilities`, `info`, `list`, `read`. Output is one JSON object per
line on stdout; errors go to stderr and yield non-zero exit codes (1 user
error, 2 storage error).

## Used by

`task parity:c-backed` (planned) — runs the strict scenario list against
both binaries and produces a drift report under `parity-reports/`.
