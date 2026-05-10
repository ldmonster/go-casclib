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

package storage

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOpenEmptyDir(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir, Options{})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()
	if s.BuildInfo != nil {
		t.Errorf("BuildInfo should be nil")
	}
	if len(s.Indexes) != 0 {
		t.Errorf("Indexes should be empty")
	}
}

func TestOpenWithBuildInfo(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".build.info"),
		[]byte("Branch!STRING:0|Version!STRING:0\nus|9.0.5\n"), 0644); err != nil {
		t.Fatal(err)
	}
	s, err := Open(dir, Options{
		ListfileReader: strings.NewReader("Interface\\Hello.lua\n"),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if s.BuildInfo == nil {
		t.Fatal("expected BuildInfo")
	}
	if got := s.BuildInfo.Get(0, "Version"); got != "9.0.5" {
		t.Errorf("version = %q", got)
	}
	if s.Listfile == nil || s.Listfile.Len() != 1 {
		t.Errorf("listfile = %v", s.Listfile)
	}
}

func TestOpenLoadsBuildConfig(t *testing.T) {
	dir := t.TempDir()
	buildKey := "5b16b5e6c3b6a3f9da0fa5d3e58d1bf7"
	cdnKey := "0123456789abcdef0123456789abcdef"
	header := "Branch!STRING:0|Version!STRING:0|Build Key!HEX:16|CDN Key!HEX:16"
	row := "us|1.0.0|" + buildKey + "|" + cdnKey
	if err := os.WriteFile(filepath.Join(dir, ".build.info"),
		[]byte(header+"\n"+row+"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	cfgDir := filepath.Join(dir, "Data", "config", buildKey[:2], buildKey[2:4])
	if err := os.MkdirAll(cfgDir, 0755); err != nil {
		t.Fatal(err)
	}
	buildCfg := `# build config
encoding = aaaabbbbccccddddeeeeffff00112233 99887766554433221100ffeeddccbbaa
root = 4d1d49e656e3835fe7be0d754a37ee44
install = 11112222333344445555666677778888 fedcba9876543210fedcba9876543210
`
	if err := os.WriteFile(filepath.Join(cfgDir, buildKey), []byte(buildCfg), 0644); err != nil {
		t.Fatal(err)
	}
	cdnCfgDir := filepath.Join(dir, "Data", "config", cdnKey[:2], cdnKey[2:4])
	_ = os.MkdirAll(cdnCfgDir, 0755)
	_ = os.WriteFile(filepath.Join(cdnCfgDir, cdnKey),
		[]byte("archives = abcdef0011223344556677889900aabb\n"), 0644)

	s, err := Open(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if s.BuildConfig == nil {
		t.Fatal("expected BuildConfig to be loaded")
	}
	if s.EncodingCKey == nil || !s.EncodingCKey.HasEKey {
		t.Errorf("EncodingCKey = %+v", s.EncodingCKey)
	}
	if s.RootCKey == nil {
		t.Error("RootCKey should be set")
	}
	if s.CDNConfig == nil {
		t.Error("CDNConfig should be loaded")
	}
}
