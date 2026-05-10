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

package casc_test

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/ldmonster/go-casclib/pkg/casc"
)

// ExampleOpenStorage demonstrates the canonical read flow: open a local
// CASC install, locate a file by name, and copy its decoded bytes to
// stdout.
func ExampleOpenStorage() {
	// Replace with the path to a local CASC install (the directory that
	// contains the .build.info file). Most users want LocaleEnUS for WoW.
	dir := os.Getenv("CASC_EXAMPLE_DIR")
	if dir == "" {
		// Skip work in unit-test runs that don't set the env var.
		fmt.Println("skipped")
		return
	}

	s, err := casc.OpenStorage(dir, casc.OpenOptions{
		LocaleMask: casc.LocaleEnUS,
	})
	if err != nil {
		fmt.Println("open:", err)
		return
	}
	defer s.Close()

	f, err := s.OpenFile(`Interface\Glues\Credits\Credits.html`)
	if err != nil {
		fmt.Println("open file:", err)
		return
	}
	defer f.Close()

	_, _ = io.Copy(io.Discard, f)
	fmt.Println("ok")
	// Output:
	// skipped
}

// ExampleStorage_FindFiles illustrates pattern-based iteration. The match
// is case-insensitive and uses path/filepath.Match semantics.
func ExampleStorage_FindFiles() {
	dir := os.Getenv("CASC_EXAMPLE_DIR")
	if dir == "" {
		fmt.Println("skipped")
		return
	}

	s, err := casc.OpenStorage(dir, casc.OpenOptions{})
	if err != nil {
		fmt.Println(err)
		return
	}
	defer s.Close()

	var n int
	_ = s.FindFiles("*.html", func(name string, _ casc.FileInfo) bool {
		if strings.HasSuffix(strings.ToLower(name), ".html") {
			n++
		}
		return true
	})
	fmt.Printf("html files: %d\n", n)
	// Output:
	// skipped
}

// ExampleStorage_AddEncryptionKey shows how to register a Salsa20 / AES
// decryption key. CascLib ships these baked in; go-casclib expects the
// caller to supply them so the library carries no proprietary key list.
func ExampleStorage_AddEncryptionKey() {
	s, err := casc.OpenStorage(os.TempDir(), casc.OpenOptions{})
	if err != nil {
		fmt.Println(err)
		return
	}
	defer s.Close()

	// 64-bit Blizzard key name → 16-byte key.
	const keyName uint64 = 0xFA505C2B7BC85E15
	key := make([]byte, 16) // real keys come from a per-build TSV
	if err := s.AddEncryptionKey(keyName, key); err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("registered")
	// Output:
	// registered
}
