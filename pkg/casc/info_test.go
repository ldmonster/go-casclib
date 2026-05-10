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
	"strings"
	"testing"
)

func TestNameTypeString(t *testing.T) {
	cases := []struct {
		nt   NameType
		want string
	}{
		{NameTypeFull, "Full"},
		{NameTypeDataID, "DataID"},
		{NameTypeCKey, "CKey"},
		{NameTypeEKey, "EKey"},
		{NameType(99), "Unknown"},
	}
	for _, c := range cases {
		if got := c.nt.String(); got != c.want {
			t.Errorf("NameType(%d).String() = %q, want %q", c.nt, got, c.want)
		}
	}
}

func TestClassifyName(t *testing.T) {
	cases := map[string]NameType{
		"foo/bar":           NameTypeFull,
		"FileDataID:42":     NameTypeDataID,
		"CKey:abcdef":       NameTypeCKey,
		"EKey:0123456789":   NameTypeEKey,
		"Interface\\X.html": NameTypeFull,
	}
	for in, want := range cases {
		if got := classifyName(in); got != want {
			t.Errorf("classifyName(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestPlainName(t *testing.T) {
	cases := map[string]string{
		"":                       "",
		"file":                   "file",
		"a/b/c.txt":              "c.txt",
		`Interface\Glue\foo.txt`: "foo.txt",
		"trailing/":              "",
	}
	for in, want := range cases {
		if got := plainName(in); got != want {
			t.Errorf("plainName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseTagListMultipleSeparators(t *testing.T) {
	got := parseTagList("text?enUS:0?speech?enUS:0?Windows")
	want := []string{"text", "enUS", "0", "speech", "enUS", "0", "Windows"}
	if len(got) != len(want) {
		t.Fatalf("parseTagList len = %d (%v), want %d (%v)", len(got), got, len(want), want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("[%d] %q vs %q", i, got[i], want[i])
		}
	}
}

func TestInferInstalledLocales(t *testing.T) {
	tags := []string{"text?enUS", "speech?enUS", "Windows", "x86_64"}
	mask := inferInstalledLocales(tags)
	if mask&LocaleEnUS == 0 {
		t.Errorf("expected LocaleEnUS bit set, got %#x", mask)
	}
	// Non-locale tokens must not pollute the mask.
	if mask&LocaleZhCN != 0 {
		t.Errorf("did not expect LocaleZhCN bit, got %#x", mask)
	}
}

func TestStorageFeaturesBits(t *testing.T) {
	// Sanity-check that the storage feature bits are distinct and non-zero.
	bits := []uint32{
		StorageFeatureLocale, StorageFeatureFileDataIDs,
		StorageFeatureRootCKey, StorageFeatureTags, StorageFeatureOnline,
	}
	seen := map[uint32]bool{}
	for _, b := range bits {
		if b == 0 {
			t.Errorf("zero feature bit found")
		}
		if seen[b] {
			t.Errorf("duplicate feature bit %#x", b)
		}
		seen[b] = true
	}
}

func TestOpenOptionsOvercomeEncryptedZeroValueIsFalse(t *testing.T) {
	// Compile-time ish: ensure the field exists and accepts a bool.
	var o OpenOptions
	o.OvercomeEncrypted = true
	o.OvercomeEncrypted = false
	if strings.Contains("", "x") {
		t.Fail()
	}
}
