# go-casclib

`go-casclib` is a Go implementation of Blizzard CASC (Content Addressable Storage Container) archive handling, with behavior aligned to [CascLib](https://github.com/ladislav-zezula/CascLib) where practical and validated by a parity harness against the C reference.

## Status

Implemented and usable today:

- Open local CASC storages (`casc.OpenStorage`)
- List files (`(*Storage).FindFiles`)
- Read files by name, CKey, EKey, or FileDataID (`OpenFile`, `OpenFileByCKey`, `OpenFileByEKey`, `OpenFileByID`)
- Storage info (`(*Storage).GetInfo`)
- Encryption key registry (`(*Storage).AddEncryptionKey`)
- Context-aware reads (`OpenFileContext`, `ReadByCKeyContext`, etc.)
- Write support: create storage, add/remove/rename files, flush (`CreateStorage`, `AddFile`, `RemoveFile`, `RenameFile`, `Flush`)
- Online CDN mode with archive set and local cache
- Root handlers: WoW (TVFS + FileDataID), Diablo III, Overwatch (CMF), MNDX (Heroes of the Storm), Install, Text
- BLTE frame decoding (copy, zlib, bzip2, lzma, Salsa20-encrypted)
- Full ENCODING, DOWNLOAD, INSTALL manifest read/write

Known partial / unsupported:

- Patch-chain archives
- A subset of encryption combinations (unsupported codecs return typed errors)

## Installation

```
go get github.com/ldmonster/go-casclib
```

## Quick start (read)

```go
package main

import (
    "fmt"
    "io"
    "log"
    "os"

    "github.com/ldmonster/go-casclib/pkg/casc"
)

func main() {
    s, err := casc.OpenStorage("/path/to/install", casc.OpenOptions{
        LocaleMask: casc.LocaleEnUS,
    })
    if err != nil {
        log.Fatal(err)
    }
    defer s.Close()

    files, err := s.FindFiles("", casc.FindOptions{})
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("files: %d\n", len(files))

    f, err := s.OpenFile("interface/glues/credits/credits.html")
    if err != nil {
        log.Fatal(err)
    }
    defer f.Close()

    io.Copy(os.Stdout, f)
}
```

## Quick start (create + write)

```go
package main

import (
    "log"

    "github.com/ldmonster/go-casclib/pkg/casc"
)

func main() {
    s, err := casc.CreateStorage("/path/to/new-storage", casc.CreateOptions{})
    if err != nil {
        log.Fatal(err)
    }
    defer s.Close()

    if err := s.AddFile("hello.txt", []byte("hello")); err != nil {
        log.Fatal(err)
    }
    if err := s.Flush(); err != nil {
        log.Fatal(err)
    }
}
```

## Repository layout

| Path | Description |
|---|---|
| `pkg/casc` | Public Go API. Start here for application-level usage. |
| `internal` | Private implementation packages (not importable from outside the module). |
| `internal/archive` | CASC data segment (`.data.NNN`) read/write and BLTE decoding engine. |
| `internal/storage` | Orchestration layer: `.build.info` → configs → ENCODING → ROOT → index lookup. |
| `internal/encoding` | ENCODING manifest read/write. |
| `internal/index` | Local `.idx` index file read/write. |
| `internal/buildcfg` | Build-config and CDN-config parsing. |
| `internal/cdn` | Online CDN client, archive index, download manifest. |
| `internal/root` | Root handler registry. |
| `internal/root/wow` | WoW TVFS + FileDataID root handler. |
| `internal/root/tvfs` | TVFS read/write. |
| `internal/root/diablo3` | Diablo III root handler. |
| `internal/root/overwatch` | Overwatch CMF root handler. |
| `internal/root/mndx` | MNDX Patricia-trie root handler (HotS / SC2 / WC3:R). |
| `internal/root/install` | Install manifest root handler. |
| `internal/compress` | Pure-Go codec ports (zlib, bzip2, lzma). |
| `internal/decrypt` | Salsa20 decryption and key registry. |
| `internal/datafile` | BLTE frame encoder/decoder. |
| `internal/hashes` | Jenkins hash and related utilities. |
| `internal/listfile` | Listfile loader. |
| `tools` | Out-of-tree binaries and parity tooling. |
| `tools/parity` | Parity test suites + drift scripts and the parity-command contract. |
| `tools/paritycmd` | `casc-parity`: in-repo Go implementation of the parity contract. |
| `tools/casclib-parity-c` | `casclib-parity-c`: native CascLib-backed implementation of the parity contract. |
| `tools/paritydiff` | Drift comparator between Go and native parity outputs. |
| `CascLib` | Vendored upstream CascLib C/C++ source tree (git submodule). |

## Development

This repository ships a Taskfile for common workflows:

| Task | Description |
|---|---|
| `task test` | Full local CI: vet, fmt, lint, unit tests, race tests. |
| `task go:test` | Run all Go tests. |
| `task go:race` | Run race-enabled tests for core packages. |
| `task lint` | Run golangci-lint with the repo config. |
| `task parity:build` | Build `bin/casc-parity` (Go). |
| `task cparity:build` | Build `build/casclib-parity-c` (native, requires cmake + CascLib submodule). |
| `task parity:structured` | Structured parity suite + JSON reports. |
| `task parity:c-backed` | Strict suite vs C binary, produce drift diff. |
| `task parity:diff` | Diff Go vs. native CascLib parity output for a fixture. |
| `task parity:mndx` | Cross-validate MNDX fixtures. |
| `task fuzz` | Run all fuzz targets sequentially (~20s each). |

`task --list` enumerates every task.

## Parity tooling

Validation against CascLib is built around a small CLI contract (currently `v0.1.0-contract1`). Two implementations of the contract live in this tree:

- [tools/paritycmd](tools/paritycmd/main.go) — Go (`bin/casc-parity`).
- [tools/casclib-parity-c](tools/casclib-parity-c/main.cpp) — native C++ against CascLib (`build/casclib-parity-c`).

The same Go test suite under [tools/parity](tools/parity/) drives both, and the drift report between them is the source of truth for behavioral parity.

For MNDX-bearing installs (Heroes of the Storm / StarCraft II / Warcraft III: Reforged) a dedicated cross-validation harness lives in [tools/parity/mndx_test.go](tools/parity/mndx_test.go):

```
export CASC_PARITY_MNDX_FIXTURES=/path/to/HotS:/path/to/SC2
export CASC_PARITY_MNDX_READ=50   # optional: SHA-256 N common files via both
task parity:mndx
```

## License

This repository vendors / includes the upstream casclib source tree. See the project and upstream repository metadata for licensing details.
