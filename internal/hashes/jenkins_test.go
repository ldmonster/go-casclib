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

package hashes

import "testing"

// Test vectors generated from the original lookup3.c reference implementation.
// hashlittle("", 0)              = 0xdeadbeef
// hashlittle("", 0xffffffff)     = 0x13464b32 (computed: 0xdeadbeef + length(0) + initval, returns c immediately)
// Actually for empty input, it returns c = 0xdeadbeef + 0 + initval before any mix.
// hashlittle("Four score and seven years ago", 0) is a known test vector.
func TestHashLittleEmpty(t *testing.T) {
	if got := HashLittle(nil, 0); got != 0xdeadbeef {
		t.Errorf("HashLittle(nil, 0) = %#x, want 0xdeadbeef", got)
	}
	if got := HashLittle(nil, 1); got != 0xdeadbef0 {
		t.Errorf("HashLittle(nil, 1) = %#x, want 0xdeadbef0", got)
	}
}

func TestHashLittleKnownVectors(t *testing.T) {
	// Known reference vectors from lookup3.c SELF_TEST output.
	cases := []struct {
		key     string
		initval uint32
		want    uint32
	}{
		{"Four score and seven years ago", 0, 0x17770551},
		{"Four score and seven years ago", 1, 0xcd628161},
	}
	for _, tc := range cases {
		if got := HashLittle([]byte(tc.key), tc.initval); got != tc.want {
			t.Errorf("HashLittle(%q, %#x) = %#x, want %#x",
				tc.key, tc.initval, got, tc.want)
		}
	}
}

func TestHashLittle2Consistency(t *testing.T) {
	// hashlittle2 with pb=0 must yield the same primary as hashlittle.
	for _, s := range []string{"", "a", "ab", "hello world", "Four score and seven years ago"} {
		want := HashLittle([]byte(s), 0)
		got, _ := HashLittle2([]byte(s), 0, 0)
		if got != want {
			t.Errorf("HashLittle2(%q) primary = %#x, HashLittle = %#x", s, got, want)
		}
	}
}

func TestRotInvariant(t *testing.T) {
	if rot(1, 1) != 2 {
		t.Errorf("rot broken")
	}
	if rot(0x80000000, 1) != 1 {
		t.Errorf("rot wraparound broken")
	}
}
