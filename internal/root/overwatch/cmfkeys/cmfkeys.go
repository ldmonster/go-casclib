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

// Package cmfkeys provides a best-effort built-in table of per-build AES
// key/IV recipes for Overwatch Content Manifest Files (CMF).
//
// Background: Blizzard ships a different AES-256 key and IV derivation
// recipe for each Overwatch game build. CascLib encodes the 13 K-LOC table
// in src/overwatch/cmf-key.cpp; the upstream of that table is TACTLib,
// generated from per-build C# source files (ProCMF_<build>.cs).
//
// What this package ships:
//
//   - The full 179-entry table of raw 512-byte keytables, generated from
//     the C++ source by tools/cmfkeygen/main.py — see
//     keytables_generated.go.
//   - The full 179-entry table of generated Key()/IV() recipe functions,
//     transpiled from the same C++ source by tools/cmfkeygen — see
//     keyfuncs_generated.go. The transpilation is mechanical; semantics
//     are best-effort and not byte-validated against TACTLib fixtures.
//   - A KeyTable(build) accessor so callers writing a custom
//     KeyProvider can fetch the byte table without copying it out of
//     CascLib by hand.
//   - DefaultRegistry, an overwatch.KeyRegistry pre-populated for every
//     known build with a provider that runs the generated recipes.
//     Callers who suspect a recipe is wrong can override per-build
//     providers via DefaultRegistry.Register(build, customProvider).
//
// C++ reference: CascLib/src/overwatch/cmf-key.cpp
package cmfkeys

import (
	"fmt"

	"github.com/ldmonster/go-casclib/internal/root/overwatch"
)

// KeyTable returns a copy of the 512-byte CMF keytable for the given
// build, or false if the build is not in the built-in set.
func KeyTable(build uint32) ([512]byte, bool) {
	t, ok := builtinKeytables[build]
	return t, ok
}

// KnownBuilds returns the sorted list of builds with a built-in keytable.
func KnownBuilds() []uint32 {
	out := make([]uint32, 0, len(builtinKeytables))
	for b := range builtinKeytables {
		out = append(out, b)
	}

	// Insertion sort — n is small (~179) and avoids importing sort.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j-1] > out[j]; j-- {
			out[j-1], out[j] = out[j], out[j-1]
		}
	}

	return out
}

// DefaultRegistry is the package-level registry. Each known build gets a
// placeholder provider that returns an error directing callers to
// register their own. Callers can override per-build providers with
// DefaultRegistry.Register(build, customProvider).
var DefaultRegistry = overwatch.NewKeyRegistry()

func init() {
	for build := range builtinKeytables {
		b := build
		DefaultRegistry.Register(b, makeProvider(b))
	}
}

func makeProvider(build uint32) overwatch.KeyProvider {
	return func(hdr overwatch.CMFHeader, digest [20]byte) ([32]byte, [16]byte, error) {
		kt, ok := builtinKeytables[build]
		if !ok {
			return [32]byte{}, [16]byte{}, fmt.Errorf(
				"cmfkeys: build %d not in built-in keytable set", build,
			)
		}

		kf, ok := builtinKeyFuncs[build]
		if !ok {
			return [32]byte{}, [16]byte{}, fmt.Errorf(
				"cmfkeys: build %d has no generated Key recipe", build,
			)
		}

		ivf, ok := builtinIVFuncs[build]
		if !ok {
			return [32]byte{}, [16]byte{}, fmt.Errorf(
				"cmfkeys: build %d has no generated IV recipe", build,
			)
		}

		var key [32]byte

		var iv [16]byte

		kf(hdr, &kt, key[:], len(key))
		ivf(hdr, &kt, digest, iv[:], len(iv))

		return key, iv, nil
	}
}
