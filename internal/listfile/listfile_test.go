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

package listfile

import (
	"strings"
	"testing"
)

func TestListfileBasic(t *testing.T) {
	src := `# comment
Interface\FrameXML\Hello.lua
Path/With/Forward/Slashes.bin

`
	l, err := Load(strings.NewReader(src))
	if err != nil {
		t.Fatal(err)
	}
	if l.Len() != 2 {
		t.Errorf("len = %d, want 2", l.Len())
	}
	// Both forms hash equal:
	if got := l.LookupName("interface/framexml/HELLO.LUA"); got == "" {
		t.Errorf("normalization failed")
	}
}

func TestHashFileNameCaseAndSlash(t *testing.T) {
	a := HashFileName("foo/bar")
	b := HashFileName("FOO\\BAR")
	if a != b {
		t.Errorf("normalization mismatch: %x vs %x", a, b)
	}
}
