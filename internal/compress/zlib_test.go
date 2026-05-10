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
	"testing"
)

func TestInflateRoundTrip(t *testing.T) {
	want := []byte("the quick brown fox jumps over the lazy dog, repeated repeated repeated")
	enc, err := Deflate(want)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Inflate(enc, len(want))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("roundtrip mismatch")
	}
}

func TestInflateBadInput(t *testing.T) {
	if _, err := Inflate([]byte{0, 1, 2, 3}, 0); err == nil {
		t.Errorf("expected error for bad zlib input")
	}
}
