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
	"io"
	"testing"
)

func TestCreateStorageInMemory(t *testing.T) {
	st, err := CreateStorage("", CreateOptions{})
	if err != nil {
		t.Fatalf("CreateStorage: %v", err)
	}
	defer st.Close()

	if err := st.AddFile("foo/bar.txt", []byte("hello")); err != nil {
		t.Fatalf("AddFile: %v", err)
	}

	// Duplicate add → ErrAlreadyExists.
	if err := st.AddFile("FOO/Bar.txt", []byte("dup")); !errors.Is(err, ErrAlreadyExists) {
		t.Errorf("duplicate AddFile: expected ErrAlreadyExists, got %v", err)
	}

	// OpenFile (case-insensitive) returns the bytes.
	f, err := st.OpenFile("Foo/Bar.txt")
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}

	got, err := io.ReadAll(f)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}

	if string(got) != "hello" {
		t.Errorf("read mismatch: %q", got)
	}

	_ = f.Close()

	// FindFiles enumerates the overlay.
	var found int
	err = st.FindFiles("*", func(_ string, _ FileInfo) bool {
		found++
		return true
	})
	if err != nil {
		t.Fatalf("FindFiles: %v", err)
	}

	if found != 1 {
		t.Errorf("FindFiles yielded %d entries, want 1", found)
	}
}

func TestRemoveFile(t *testing.T) {
	st, _ := CreateStorage("", CreateOptions{})
	defer st.Close()

	_ = st.AddFile("a.bin", []byte{1, 2, 3})

	if err := st.RemoveFile("a.bin"); err != nil {
		t.Fatalf("RemoveFile: %v", err)
	}

	if _, err := st.OpenFile("a.bin"); !errors.Is(err, ErrFileNotFound) {
		t.Errorf("OpenFile after remove: expected ErrFileNotFound, got %v", err)
	}
}

func TestRenameOverlay(t *testing.T) {
	st, _ := CreateStorage("", CreateOptions{})
	defer st.Close()

	_ = st.AddFile("orig.txt", []byte("body"))

	if err := st.RenameFile("orig.txt", "new.txt"); err != nil {
		t.Fatalf("RenameFile: %v", err)
	}

	if _, err := st.OpenFile("orig.txt"); !errors.Is(err, ErrFileNotFound) {
		t.Errorf("orig should be gone, got %v", err)
	}

	f, err := st.OpenFile("new.txt")
	if err != nil {
		t.Fatalf("OpenFile new.txt: %v", err)
	}

	got, _ := io.ReadAll(f)
	_ = f.Close()

	if string(got) != "body" {
		t.Errorf("rename body mismatch: %q", got)
	}
}

func TestRenameNoOp(t *testing.T) {
	st, _ := CreateStorage("", CreateOptions{})
	defer st.Close()

	_ = st.AddFile("x", []byte("y"))

	if err := st.RenameFile("X", "x"); err != nil {
		t.Errorf("rename to same case-folded name should be no-op, got %v", err)
	}
}

func TestRenameToExisting(t *testing.T) {
	st, _ := CreateStorage("", CreateOptions{})
	defer st.Close()

	_ = st.AddFile("a", []byte("1"))
	_ = st.AddFile("b", []byte("2"))

	if err := st.RenameFile("a", "b"); !errors.Is(err, ErrAlreadyExists) {
		t.Errorf("rename onto existing: expected ErrAlreadyExists, got %v", err)
	}
}

func TestFlushNotSupported(t *testing.T) {
	st, _ := CreateStorage("", CreateOptions{})
	if err := st.Flush(); !errors.Is(err, ErrNotSupported) {
		t.Errorf("Flush: %v", err)
	}
}

func TestInvalidNames(t *testing.T) {
	st, _ := CreateStorage("", CreateOptions{})
	defer st.Close()

	if err := st.AddFile("", nil); !errors.Is(err, ErrInvalidParameter) {
		t.Errorf("AddFile empty: %v", err)
	}

	if err := st.RemoveFile(""); !errors.Is(err, ErrInvalidParameter) {
		t.Errorf("RemoveFile empty: %v", err)
	}

	if err := st.RenameFile("", "x"); !errors.Is(err, ErrInvalidParameter) {
		t.Errorf("RenameFile empty: %v", err)
	}
}
