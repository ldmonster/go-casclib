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

package compress

import (
	"bytes"
	"errors"
	"testing"
)

func TestUnlzmaUnregistered(t *testing.T) {
	if _, err := Unlzma([]byte{0x5D, 0, 0, 1, 0}, 0); !errors.Is(err, ErrLZMAUnsupported) {
		t.Fatalf("expected ErrLZMAUnsupported, got %v", err)
	}
}

func TestLZMARegisterRoundtrip(t *testing.T) {
	if LZMARegistered() {
		t.Skip("decoder already registered")
	}

	want := []byte("hello lzma")

	SetLZMADecoder(func(in []byte, _ int) ([]byte, error) {
		// echo decoder: caller passes plaintext as "in".
		return append([]byte(nil), in...), nil
	})

	defer SetLZMADecoder(nil)

	if !LZMARegistered() {
		t.Fatal("LZMARegistered should be true")
	}

	got, err := Unlzma(want, len(want))
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(got, want) {
		t.Fatalf("roundtrip mismatch: got %q want %q", got, want)
	}
}

func TestLooksLikeLZMA(t *testing.T) {
	xz := []byte{0xFD, '7', 'z', 'X', 'Z', 0x00}
	if !LooksLikeLZMA(xz) {
		t.Error("xz magic should match")
	}

	// LZMA1: lc=3 lp=0 pb=2 → props=0x5D ; dict=0x00080000.
	lzma1 := []byte{0x5D, 0x00, 0x00, 0x08, 0x00, 0, 0, 0, 0, 0, 0, 0, 0}
	if !LooksLikeLZMA(lzma1) {
		t.Error("lzma1 header should match")
	}

	if LooksLikeLZMA([]byte{0x78, 0x9C}) { // zlib
		t.Error("zlib magic should not match")
	}

	if LooksLikeLZMA(nil) {
		t.Error("empty should not match")
	}
}
