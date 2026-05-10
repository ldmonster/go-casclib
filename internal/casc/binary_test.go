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

import "testing"

func TestBigEndianHelpers(t *testing.T) {
	b := []byte{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC}
	if got := BEUint16(b); got != 0x1234 {
		t.Errorf("BEUint16 = %#x, want 0x1234", got)
	}
	if got := BEUint24(b); got != 0x123456 {
		t.Errorf("BEUint24 = %#x, want 0x123456", got)
	}
	if got := BEUint32(b); got != 0x12345678 {
		t.Errorf("BEUint32 = %#x, want 0x12345678", got)
	}
	if got := BEUint40(b); got != 0x123456789A {
		t.Errorf("BEUint40 = %#x", got)
	}
	if got := BEUint48(b); got != 0x123456789ABC {
		t.Errorf("BEUint48 = %#x", got)
	}
}

func TestLittleEndianHelpers(t *testing.T) {
	b := []byte{0x78, 0x56, 0x34, 0x12}
	if got := LEUint32(b); got != 0x12345678 {
		t.Errorf("LEUint32 = %#x", got)
	}
	out := make([]byte, 4)
	PutLEUint32(out, 0xDEADBEEF)
	want := []byte{0xEF, 0xBE, 0xAD, 0xDE}
	for i := range want {
		if out[i] != want[i] {
			t.Errorf("PutLEUint32[%d] = %#x, want %#x", i, out[i], want[i])
		}
	}
}
