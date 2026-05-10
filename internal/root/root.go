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

package root

import (
	"github.com/ldmonster/go-casclib/internal/casc"
)

// Handler is the abstraction over a CASC root manifest. Concrete handlers
// translate logical filenames / FileDataIDs into CKey/EKey for lookup in the
// ENCODING manifest. This mirrors PCASC_ROOT_HANDLER in CascLib.
type Handler interface {
	// Name returns a short descriptor for diagnostics.
	Name() string

	// LookupByName returns the entry for a logical filename, or nil.
	LookupByName(name string) *casc.CKeyEntry

	// LookupByFileDataID returns the entry for a WoW FileDataID, or nil.
	// Handlers that don't support FDIDs return nil.
	LookupByFileDataID(id uint32) *casc.CKeyEntry

	// All iterates all entries known to the handler.
	All(yield func(name string, entry *casc.CKeyEntry) bool)

	// Features returns CASC_FEATURE_* bits supported by this handler.
	Features() uint32
}

// Probe identifies a root by sniffing a magic value at the start of the
// decoded root file. Each implementation registers a Probe.
type Probe func(rootData []byte) (Handler, error)

var registry []Probe

// Register adds a probe to the global registry.
func Register(p Probe) { registry = append(registry, p) }

// Detect returns the first handler whose Probe accepts rootData.
func Detect(rootData []byte) (Handler, error) {
	for _, p := range registry {
		h, err := p(rootData)
		if err == nil && h != nil {
			return h, nil
		}
	}

	return nil, casc.ErrNotSupported
}
