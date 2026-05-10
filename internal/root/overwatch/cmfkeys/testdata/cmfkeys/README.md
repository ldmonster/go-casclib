# Overwatch CMF key/iv parity fixtures

Drop one `<build>.json` file per Overwatch build you want to validate.
Files in this directory are not committed because the upstream key
recipes (TACTLib) are licensed separately; the parity test in
`fixtures_test.go` simply iterates whatever it finds.

## Format

```json
{
  "build":         35328,
  "data_count":    1234,
  "entry_count":   5678,
  "magic":         1667457281,
  "digest_hex":    "0102030405060708090a0b0c0d0e0f1011121314",
  "expected_key":  "<64 hex chars: 32-byte AES-256 key>",
  "expected_iv":   "<32 hex chars: 16-byte AES-256 IV>"
}
```

`digest_hex` is the 20-byte SHA1 hash of the CMF entry name (the input
to the per-build `Key()`/`IV()` functions). `data_count`, `entry_count`,
and `magic` come from the CMF header you're validating against.

## Generating a fixture from a real CMF

Use the upstream TACTLib (or a manual run of `cmf-key.cpp`) to extract
the expected key/iv for the build you want, then encode it here. The
test runs `internal/root/overwatch/cmfkeys.DefaultRegistry.Find(build)`
and asserts byte-for-byte equality against `expected_key` and
`expected_iv`.

## Skipping

When this directory is empty (or absent), `TestCMFKeyFixtures` calls
`t.Skip` so CI stays green.
