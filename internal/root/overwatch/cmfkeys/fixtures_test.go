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

package cmfkeys

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/ldmonster/go-casclib/internal/root/overwatch"
)

// fixture is the on-disk format of a per-build CMF key/iv parity record.
//
// Files live under testdata/cmfkeys/<build>.json. Fixtures are not
// committed (TACTLib is licensed separately); the test skips silently
// when the directory is empty so CI stays green.
//
// To add a fixture:
//
//	{
//	  "build":         35328,
//	  "data_count":    1234,
//	  "entry_count":   5678,
//	  "magic":         1667457281,
//	  "digest_hex":    "0102...20bytes",
//	  "expected_key":  "...64 hex chars",
//	  "expected_iv":   "...32 hex chars"
//	}
type fixture struct {
	Build       uint32 `json:"build"`
	DataCount   int32  `json:"data_count"`
	EntryCount  int32  `json:"entry_count"`
	Magic       uint32 `json:"magic"`
	DigestHex   string `json:"digest_hex"`
	ExpectedKey string `json:"expected_key"`
	ExpectedIV  string `json:"expected_iv"`
}

func TestCMFKeyFixtures(t *testing.T) {
	dir := filepath.Join("testdata", "cmfkeys")

	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			t.Skip("no testdata/cmfkeys directory; drop *.json fixtures to enable parity check")
		}
		t.Fatal(err)
	}

	var ran int

	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}

		path := filepath.Join(dir, e.Name())
		t.Run(e.Name(), func(t *testing.T) {
			fx := loadFixture(t, path)
			runFixture(t, fx)
		})
		ran++
	}

	if ran == 0 {
		t.Skip("no .json fixtures in testdata/cmfkeys")
	}
}

func loadFixture(t *testing.T, path string) fixture {
	t.Helper()

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	var fx fixture
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}

	return fx
}

func runFixture(t *testing.T, fx fixture) {
	t.Helper()

	provider := DefaultRegistry.Find(fx.Build)
	if provider == nil {
		t.Fatalf("no provider registered for build %d", fx.Build)
	}

	digest, err := decodeFixedHex(fx.DigestHex, 20)
	if err != nil {
		t.Fatalf("digest_hex: %v", err)
	}

	wantKey, err := decodeFixedHex(fx.ExpectedKey, 32)
	if err != nil {
		t.Fatalf("expected_key: %v", err)
	}

	wantIV, err := decodeFixedHex(fx.ExpectedIV, 16)
	if err != nil {
		t.Fatalf("expected_iv: %v", err)
	}

	hdr := overwatch.CMFHeader{
		BuildVersion: fx.Build,
		DataCount:    fx.DataCount,
		EntryCount:   fx.EntryCount,
		Magic:        fx.Magic,
	}

	var d20 [20]byte
	copy(d20[:], digest)

	gotKey, gotIV, err := provider(hdr, d20)
	if err != nil {
		t.Fatalf("provider: %v", err)
	}

	if gotKey != *(*[32]byte)(wantKey) {
		t.Errorf("key mismatch:\n got %x\nwant %x", gotKey, wantKey)
	}

	if gotIV != *(*[16]byte)(wantIV) {
		t.Errorf("iv mismatch:\n got %x\nwant %x", gotIV, wantIV)
	}
}

func decodeFixedHex(s string, want int) ([]byte, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}

	if len(b) != want {
		return nil, errLen{got: len(b), want: want}
	}

	return b, nil
}

type errLen struct{ got, want int }

func (e errLen) Error() string {
	return "expected " + itoa(e.want) + " bytes, got " + itoa(e.got)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}

	var buf [20]byte

	i := len(buf)

	neg := n < 0
	if neg {
		n = -n
	}

	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}

	if neg {
		i--
		buf[i] = '-'
	}

	return string(buf[i:])
}
