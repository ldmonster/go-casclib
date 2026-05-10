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
	"context"
	"errors"
	"testing"

	"github.com/ldmonster/go-casclib/pkg/casc"
)

func TestContextCancelledOpenFile(t *testing.T) {
	dir := t.TempDir()

	s, err := casc.CreateStorage(dir, casc.CreateOptions{})
	if err != nil {
		t.Fatalf("CreateStorage: %v", err)
	}

	defer func() { _ = s.Close() }()

	if err := s.AddFile("a.txt", []byte("hi")); err != nil {
		t.Fatalf("AddFile: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := s.OpenFileContext(ctx, "a.txt"); !errors.Is(err, context.Canceled) {
		t.Fatalf("want Canceled, got %v", err)
	}
}

func TestContextCancelStopsFindFiles(t *testing.T) {
	dir := t.TempDir()

	s, err := casc.CreateStorage(dir, casc.CreateOptions{})
	if err != nil {
		t.Fatalf("CreateStorage: %v", err)
	}

	defer func() { _ = s.Close() }()

	for _, n := range []string{"a", "b", "c", "d", "e"} {
		if err := s.AddFile(n, []byte(n)); err != nil {
			t.Fatalf("AddFile %s: %v", n, err)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())

	count := 0

	err = s.FindFilesContext(ctx, "*", func(_ string, _ casc.FileInfo) bool {
		count++
		if count == 2 {
			cancel()
		}

		return true
	})

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("want Canceled, got %v (count=%d)", err, count)
	}
}
