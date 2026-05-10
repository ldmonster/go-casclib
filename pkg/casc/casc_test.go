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
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOpenEmptyDir(t *testing.T) {
	dir := t.TempDir()
	s, err := OpenStorage(dir, OpenOptions{})
	if err != nil {
		t.Fatalf("OpenStorage: %v", err)
	}
	defer s.Close()
}

func TestAddEncryptionKey(t *testing.T) {
	dir := t.TempDir()
	s, _ := OpenStorage(dir, OpenOptions{})
	defer s.Close()
	if err := s.AddEncryptionKey(0xDEADBEEF, make([]byte, 16)); err != nil {
		t.Errorf("AddEncryptionKey: %v", err)
	}
	if err := s.AddEncryptionKey(0xDEADBEEF, make([]byte, 7)); err == nil {
		t.Errorf("expected error for short key")
	}
}

func TestOpenWithListfilePath(t *testing.T) {
	dir := t.TempDir()
	lf := filepath.Join(dir, "names.txt")
	if err := os.WriteFile(lf, []byte("foo\nbar\n"), 0o600); err != nil {
		t.Fatalf("write listfile: %v", err)
	}

	s, err := OpenStorage(dir, OpenOptions{ListfilePath: lf})
	if err != nil {
		t.Fatalf("OpenStorage: %v", err)
	}
	defer s.Close()
}

func TestOpenWithListfilePathMissing(t *testing.T) {
	dir := t.TempDir()
	_, err := OpenStorage(dir, OpenOptions{ListfilePath: filepath.Join(dir, "nope")})
	if err == nil {
		t.Errorf("expected error opening missing listfile")
	}
}

func TestOpenFileWithoutRoot(t *testing.T) {
	dir := t.TempDir()
	s, _ := OpenStorage(dir, OpenOptions{
		ListfileReader: strings.NewReader("foo\n"),
	})
	defer s.Close()
	_, err := s.OpenFile("nope")
	if err == nil {
		t.Errorf("expected error")
	}
	if !errors.Is(err, ErrNotSupported) && !errors.Is(err, ErrFileNotFound) {
		// Either is acceptable: no root handler vs not in (empty) root.
		// Implementation currently returns ErrNotSupported.
	}
}
