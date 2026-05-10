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

package csv

import (
	"strings"
	"testing"
)

const sample = `Branch!STRING:0|Active!DEC:1|Build Key!HEX:16|CDN Key!HEX:16|Version!STRING:0
us|1|abcd|efgh|1.0.0
eu|0|wxyz|1234|2.0.0
`

func TestParseBuildInfo(t *testing.T) {
	f, err := Parse(strings.NewReader(sample))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := f.Headers[0], "Branch"; got != want {
		t.Errorf("header[0] = %q, want %q", got, want)
	}
	if len(f.Rows) != 2 {
		t.Fatalf("rows = %d", len(f.Rows))
	}
	if got, want := f.Get(1, "Version"), "2.0.0"; got != want {
		t.Errorf("Get = %q", got)
	}
	if f.Column("Missing") != -1 {
		t.Errorf("missing col not -1")
	}
}
