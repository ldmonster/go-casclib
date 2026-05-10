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

package casc

import (
	"strings"
	"testing"

	internalcasc "github.com/ldmonster/go-casclib/internal/casc"
	"github.com/ldmonster/go-casclib/internal/storage"
)

// syntheticRoot builds a dummy root.Handler with n entries for benchmarking.
type syntheticRoot struct {
	entries []namedEntry
}

type namedEntry struct {
	name string
	ck   internalcasc.CKeyEntry
}

func (r *syntheticRoot) Name() string { return "synthetic" }

func (r *syntheticRoot) LookupByName(name string) *internalcasc.CKeyEntry {
	for i := range r.entries {
		if r.entries[i].name == name {
			return &r.entries[i].ck
		}
	}

	return nil
}

func (r *syntheticRoot) LookupByFileDataID(_ uint32) *internalcasc.CKeyEntry { return nil }
func (r *syntheticRoot) Features() uint32                                    { return 0 }

func (r *syntheticRoot) All(yield func(name string, entry *internalcasc.CKeyEntry) bool) {
	for i := range r.entries {
		if !yield(r.entries[i].name, &r.entries[i].ck) {
			return
		}
	}
}

func buildSyntheticStorage(b *testing.B, n int) *Storage {
	b.Helper()

	entries := make([]namedEntry, n)
	for i := range entries {
		entries[i] = namedEntry{
			name: strings.Repeat("a", i%16+1) + ".blp",
		}
	}

	inner := &storage.Storage{}
	inner.Root = &syntheticRoot{entries: entries}

	return &Storage{inner: inner}
}

// BenchmarkFindFiles measures iteration over a root with 10 000 entries.
func BenchmarkFindFiles(b *testing.B) {
	s := buildSyntheticStorage(b, 10_000)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = s.FindFiles("", func(_ string, _ FileInfo) bool { return true })
	}
}

// BenchmarkFindFilesPattern measures pattern-filtered iteration.
func BenchmarkFindFilesPattern(b *testing.B) {
	s := buildSyntheticStorage(b, 10_000)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = s.FindFiles("*.blp", func(_ string, _ FileInfo) bool { return true })
	}
}

// BenchmarkGetStorageInfo measures the GetInfo call.
func BenchmarkGetStorageInfo(b *testing.B) {
	s := buildSyntheticStorage(b, 1_000)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = s.GetInfo()
	}
}

// BenchmarkFileRead measures the Read path on a pre-populated File.
func BenchmarkFileRead(b *testing.B) {
	data := make([]byte, 64*1024)

	f := &File{content: data}

	buf := make([]byte, 4096)

	b.SetBytes(int64(len(data)))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		f.pos = 0

		for {
			n, err := f.Read(buf)
			if n == 0 || err != nil {
				break
			}
		}
	}
}
