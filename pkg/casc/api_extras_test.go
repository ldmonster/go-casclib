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
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/ldmonster/go-casclib/pkg/casc"
)

// TestReadByCKeyAndEKeyRoundTrip exercises ReadByCKey and ReadByEKey on a
// CreateStorage+Flush round-trip, since those storages have a working
// ENCODING manifest and local index.
func TestReadByCKeyAndEKeyRoundTrip(t *testing.T) {
	dir := t.TempDir()

	w, err := casc.CreateStorage(dir, casc.CreateOptions{})
	if err != nil {
		t.Fatalf("CreateStorage: %v", err)
	}

	body := []byte("ReadByCKey roundtrip payload")
	if err := w.AddFile("foo.bin", body); err != nil {
		t.Fatalf("AddFile: %v", err)
	}

	if err := w.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	_ = w.Close()

	r, err := casc.OpenStorage(dir, casc.OpenOptions{})
	if err != nil {
		t.Fatalf("OpenStorage: %v", err)
	}
	defer r.Close()

	// Find the file's CKey/EKey via FindFiles.
	var ck, ek [16]byte
	var found bool
	_ = r.FindFiles("foo.bin", func(name string, info casc.FileInfo) bool {
		if name == "foo.bin" {
			ck = info.ContentKey
			ek = info.EncodedKey
			found = true
			return false
		}
		return true
	})
	if !found {
		t.Fatalf("foo.bin not found in iteration")
	}

	got, err := r.ReadByCKey(ck)
	if err != nil {
		t.Fatalf("ReadByCKey: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Errorf("ReadByCKey body mismatch (%d bytes)", len(got))
	}

	got2, err := r.ReadByEKey(ek)
	if err != nil {
		t.Fatalf("ReadByEKey: %v", err)
	}
	if !bytes.Equal(got2, body) {
		t.Errorf("ReadByEKey body mismatch (%d bytes)", len(got2))
	}

	// Context cancellation
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := r.ReadByCKeyContext(ctx, ck); !errors.Is(err, context.Canceled) {
		t.Errorf("ReadByCKeyContext after cancel: %v", err)
	}
	if _, err := r.ReadByEKeyContext(ctx, ek); !errors.Is(err, context.Canceled) {
		t.Errorf("ReadByEKeyContext after cancel: %v", err)
	}
}

func TestReadByCKeyMissing(t *testing.T) {
	dir := t.TempDir()

	w, _ := casc.CreateStorage(dir, casc.CreateOptions{})
	_ = w.AddFile("a", []byte("x"))
	_ = w.Flush()
	_ = w.Close()

	r, err := casc.OpenStorage(dir, casc.OpenOptions{})
	if err != nil {
		t.Fatalf("OpenStorage: %v", err)
	}
	defer r.Close()

	var bogus [16]byte
	for i := range bogus {
		bogus[i] = 0xFE
	}
	if _, err := r.ReadByCKey(bogus); !errors.Is(err, casc.ErrFileNotFound) {
		t.Errorf("ReadByCKey on bogus key: got %v, want ErrFileNotFound", err)
	}
}

// TestStorageGetInfoFields cross-validates that GetInfo reflects build.info
// fields after a CreateStorage round-trip.
func TestStorageGetInfoFields(t *testing.T) {
	dir := t.TempDir()

	w, _ := casc.CreateStorage(dir, casc.CreateOptions{})
	_ = w.AddFile("file.txt", []byte("hi"))
	_ = w.Flush()
	_ = w.Close()

	r, _ := casc.OpenStorage(dir, casc.OpenOptions{})
	defer r.Close()

	si := r.GetInfo()
	if si.Path != dir {
		t.Errorf("GetInfo.Path = %q, want %q", si.Path, dir)
	}
	if si.Product == "" {
		t.Errorf("GetInfo.Product empty for synthetic build")
	}
	if si.Region == "" {
		t.Errorf("GetInfo.Region empty for synthetic build")
	}
	if si.RootType == "" {
		t.Errorf("GetInfo.RootType empty after round-trip")
	}
	// Open-call should imply Online feature is NOT set (no CDN).
	if si.Features&casc.StorageFeatureOnline != 0 {
		t.Errorf("Online feature unexpectedly set: %#x", si.Features)
	}
}

// TestFindFilesPlainNameAndNameType verifies that FindFiles populates the
// new diagnostic fields on FileInfo.
func TestFindFilesPlainNameAndNameType(t *testing.T) {
	dir := t.TempDir()
	w, _ := casc.CreateStorage(dir, casc.CreateOptions{})
	_ = w.AddFile("dir/sub/leaf.bin", []byte("X"))
	_ = w.Flush()
	_ = w.Close()

	r, _ := casc.OpenStorage(dir, casc.OpenOptions{})
	defer r.Close()

	var info casc.FileInfo
	var matched int
	_ = r.FindFiles("", func(_ string, fi casc.FileInfo) bool {
		if strings.HasSuffix(fi.FileName, "leaf.bin") {
			info = fi
			matched++
		}
		return true
	})
	if matched == 0 {
		t.Fatalf("FindFiles did not yield leaf.bin")
	}
	if info.PlainName != "leaf.bin" {
		t.Errorf("PlainName = %q, want leaf.bin", info.PlainName)
	}
	if info.NameType != casc.NameTypeFull {
		t.Errorf("NameType = %v, want NameTypeFull", info.NameType)
	}
	if !info.Available {
		t.Errorf("Available = false, want true (file in local index)")
	}
}

// TestOpenOptionsOvercomeEncryptedPassthrough exercises the option path
// even though no encrypted span is present (round-trips with the option
// set are expected to behave identically to the default).
func TestOpenOptionsOvercomeEncryptedPassthrough(t *testing.T) {
	dir := t.TempDir()
	w, _ := casc.CreateStorage(dir, casc.CreateOptions{})
	_ = w.AddFile("plain.txt", []byte("plain bytes"))
	_ = w.Flush()
	_ = w.Close()

	r, err := casc.OpenStorage(dir, casc.OpenOptions{OvercomeEncrypted: true})
	if err != nil {
		t.Fatalf("OpenStorage: %v", err)
	}
	defer r.Close()

	f, err := r.OpenFile("plain.txt")
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	got, _ := io.ReadAll(f)
	_ = f.Close()
	if string(got) != "plain bytes" {
		t.Errorf("body mismatch: %q", got)
	}
}
