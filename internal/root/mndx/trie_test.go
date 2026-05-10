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

package mndx

import "testing"

func TestSetBitsAll(t *testing.T) {
	cases := []struct {
		v   uint32
		l8  uint32
		l16 uint32
		l24 uint32
		l32 uint32
	}{
		{0x00000000, 0, 0, 0, 0},
		{0x000000FF, 8, 8, 8, 8},
		{0x0000FFFF, 8, 16, 16, 16},
		{0x00FFFFFF, 8, 16, 24, 24},
		{0xFFFFFFFF, 8, 16, 24, 32},
		{0xAAAAAAAA, 4, 8, 12, 16},
	}
	for _, c := range cases {
		v := setBitsAll(c.v)
		if v&0xFF != c.l8 || (v>>8)&0xFF != c.l16 || (v>>16)&0xFF != c.l24 || (v>>24)&0xFF != c.l32 {
			t.Errorf("setBitsAll(%#x) = %#x, want lower08=%d lower16=%d lower24=%d lower32=%d",
				c.v, v, c.l8, c.l16, c.l24, c.l32)
		}
	}
}

func TestBitPos8Table(t *testing.T) {
	// For byte b, the (n+1)-th set bit position should match a
	// straightforward enumeration.
	for b := 0; b < 256; b++ {
		positions := []byte{}
		for i := 0; i < 8; i++ {
			if b&(1<<i) != 0 {
				positions = append(positions, byte(i))
			}
		}
		for n := 0; n < 8; n++ {
			got := bitPos8Table[(n<<8)|b]
			var want byte = 7
			if n < len(positions) {
				want = positions[n]
			}
			if got != want {
				t.Errorf("bitPos8Table[n=%d, b=%#02x] = %d, want %d", n, b, got, want)
			}
		}
	}
}

func TestPopcount32(t *testing.T) {
	cases := map[uint32]uint32{0: 0, 1: 1, 0xFF: 8, 0xFFFF: 16, 0xFFFFFFFF: 32, 0xCAFEBABE: 22}
	for v, want := range cases {
		if got := popcount32(v); got != want {
			t.Errorf("popcount32(%#x) = %d, want %d", v, got, want)
		}
	}
}
