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

package storage

import (
	"bytes"
	"path/filepath"
	"testing"
)

func TestCachePath(t *testing.T) {
	got := cachePath("/tmp/cache", "abcdef0123456789")

	want := filepath.Join("/tmp/cache", "ab", "cd", "abcdef0123456789")
	if got != want {
		t.Errorf("cachePath: got %q, want %q", got, want)
	}
}

func TestCacheReadWriteRoundtrip(t *testing.T) {
	dir := t.TempDir()

	s := &Storage{opts: Options{CacheDir: dir}}

	hexKey := "deadbeefcafebabe11223344"
	want := []byte("hello cache")

	if err := s.cacheWrite(hexKey, want); err != nil {
		t.Fatalf("cacheWrite: %v", err)
	}

	got, err := s.cacheRead(hexKey)
	if err != nil {
		t.Fatalf("cacheRead: %v", err)
	}

	if !bytes.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestCacheDisabled(t *testing.T) {
	s := &Storage{opts: Options{}}

	if err := s.cacheWrite("abcd", []byte("x")); err != nil {
		t.Errorf("cacheWrite with empty CacheDir should be no-op, got %v", err)
	}

	if _, err := s.cacheRead("abcd"); err == nil {
		t.Error("cacheRead with empty CacheDir should error")
	}
}

func TestEKeyHex(t *testing.T) {
	var e [16]byte
	for i := range e {
		e[i] = byte(i)
	}

	got := ekeyHex(e)

	want := "000102030405060708090a0b0c0d0e0f"
	if got != want {
		t.Errorf("ekeyHex: got %q, want %q", got, want)
	}
}
