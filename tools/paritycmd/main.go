// Copyright 2026 go-casclib Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Command casc-parity is the parity-contract binary for go-casclib.
//
// It exposes a small JSON-line protocol so that the same test suite can
// drive both this Go implementation and a native CascLib binary
// (tools/casclib-parity-c) and diff their outputs.
//
// Subcommands
//
//	casc-parity capabilities
//	    Print {"impl":"go", "version":"...", ...}.
//
//	casc-parity info <storage-dir>
//	    Print one JSON object describing the storage:
//	    {"impl","root_type","file_count","build","cdn_path"}.
//
//	casc-parity list <storage-dir> [pattern]
//	    Print one JSON object per file:
//	    {"name","ckey","ekey","content_size","encoded_size","file_data_id"}.
//
//	casc-parity read <storage-dir> <filename>
//	    Print one JSON object: {"name","sha256","size","hex_first_bytes"}.
//	    Raw bytes are not piped to keep the protocol line-oriented.
//
// All subcommands write JSON Lines to stdout and human errors to stderr.
// Exit codes: 0 success, 1 user error, 2 file/storage error.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"

	"github.com/ldmonster/go-casclib/pkg/casc"
)

const parityVersion = "0.1.0"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "casc-parity:", err)

		var ue *userError
		if errors.As(err, &ue) {
			os.Exit(1)
		}

		os.Exit(2)
	}
}

type userError struct{ msg string }

func (e *userError) Error() string { return e.msg }

func userErrorf(format string, args ...any) error {
	return &userError{msg: fmt.Sprintf(format, args...)}
}

func run(args []string) error {
	if len(args) == 0 {
		return userErrorf("usage: casc-parity <capabilities|info|list|read> ...")
	}

	switch args[0] {
	case "capabilities":
		return cmdCapabilities()
	case "info":
		if len(args) < 2 {
			return userErrorf("usage: casc-parity info <storage-dir>")
		}

		return cmdInfo(args[1])
	case "list":
		if len(args) < 2 {
			return userErrorf("usage: casc-parity list <storage-dir> [pattern]")
		}

		pattern := ""
		if len(args) >= 3 {
			pattern = args[2]
		}

		return cmdList(args[1], pattern)
	case "read":
		if len(args) < 3 {
			return userErrorf("usage: casc-parity read <storage-dir> <filename>")
		}

		return cmdRead(args[1], args[2])
	default:
		return userErrorf("unknown subcommand %q", args[0])
	}
}

func emit(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)

	return enc.Encode(v)
}

func cmdCapabilities() error {
	return emit(os.Stdout, map[string]any{
		"impl":           "go-casclib",
		"version":        parityVersion,
		"go_version":     runtime.Version(),
		"protocol":       "v0.1.0",
		"subcommands":    []string{"capabilities", "info", "list", "read"},
		"supports_glob":  true,
		"supports_read":  true,
		"online_capable": false,
	})
}

func openStorage(dir string) (*casc.Storage, error) {
	st, err := casc.OpenStorage(dir, casc.OpenOptions{})
	if err != nil {
		return nil, fmt.Errorf("open %q: %w", dir, err)
	}

	return st, nil
}

func cmdInfo(dir string) error {
	st, err := openStorage(dir)
	if err != nil {
		return err
	}
	defer st.Close()

	count := 0

	if err := st.FindFiles("", func(string, casc.FileInfo) bool {
		count++
		return true
	}); err != nil && !errors.Is(err, casc.ErrNotSupported) {
		return err
	}

	si := st.GetInfo()

	return emit(os.Stdout, map[string]any{
		"impl":          "go-casclib",
		"file_count":    count,
		"dir":           dir,
		"root_type":     si.RootType,
		"build_version": si.BuildVersion,
		"cdn_path":      si.CDNPath,
	})
}

func cmdList(dir, pattern string) error {
	st, err := openStorage(dir)
	if err != nil {
		return err
	}
	defer st.Close()

	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)

	if err := st.FindFiles(pattern, func(name string, info casc.FileInfo) bool {
		_ = enc.Encode(map[string]any{
			"name":         name,
			"ckey":         hex.EncodeToString(info.ContentKey[:]),
			"ekey":         hex.EncodeToString(info.EncodedKey[:]),
			"content_size": info.ContentSize,
			"encoded_size": info.EncodedSize,
			"file_data_id": info.FileDataID,
		})

		return true
	}); err != nil && !errors.Is(err, casc.ErrNotSupported) {
		return err
	}

	return nil
}

func cmdRead(dir, name string) error {
	st, err := openStorage(dir)
	if err != nil {
		return err
	}
	defer st.Close()

	f, err := st.OpenFile(name)
	if err != nil {
		return fmt.Errorf("open file %q: %w", name, err)
	}
	defer f.Close()

	data, err := io.ReadAll(f)
	if err != nil {
		return fmt.Errorf("read %q: %w", name, err)
	}

	sum := sha256.Sum256(data)

	head := data
	if len(head) > 64 {
		head = head[:64]
	}

	return emit(os.Stdout, map[string]any{
		"name":            name,
		"size":            len(data),
		"sha256":          hex.EncodeToString(sum[:]),
		"hex_first_bytes": hex.EncodeToString(head),
	})
}
