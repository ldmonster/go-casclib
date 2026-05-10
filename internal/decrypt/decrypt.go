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

package decrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"sync"

	"github.com/ldmonster/go-casclib/internal/casc"
)

// KeyRegistry maps 64-bit KeyName -> 16-byte key. It is goroutine-safe.
type KeyRegistry struct {
	mu   sync.RWMutex
	keys map[uint64][]byte
}

// NewKeyRegistry creates a new empty registry.
func NewKeyRegistry() *KeyRegistry {
	return &KeyRegistry{keys: make(map[uint64][]byte)}
}

// Add registers a key. The key must be 16 bytes (Salsa20-128 / AES-128).
func (r *KeyRegistry) Add(name uint64, key []byte) error {
	if len(key) != 16 {
		return fmt.Errorf("%w: key must be 16 bytes, got %d", casc.ErrInvalidParameter, len(key))
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	cp := make([]byte, 16)
	copy(cp, key)
	r.keys[name] = cp

	return nil
}

// Find returns the key bytes for the given name, or nil if not registered.
func (r *KeyRegistry) Find(name uint64) []byte {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return r.keys[name]
}

// Frame implements the encrypted-frame ('E' BLTE mode) wire format. The input
// is the bytes of the frame after the 'E' mode byte was stripped:
//
//	[1] KeyNameSize (0 or 8)
//	[KeyNameSize] KeyName (little-endian)
//	[1] IVSize (4 or 8)
//	[IVSize] IV
//	[1] EncryptionType ('S' Salsa20 or 'A' AES — only 'S' is supported)
//	[*] ciphertext
//
// The IV is XORed with frameIndex (low bytes first).
//
// On unknown key, returns ErrEncrypted; on bad format, ErrBadFormat.
func (r *KeyRegistry) DecryptFrame(in []byte, frameIndex int) ([]byte, error) {
	if len(in) < 1 {
		return nil, casc.ErrFileCorrupt
	}

	keyNameSize := int(in[0])
	if keyNameSize != 0 && keyNameSize != 8 {
		return nil, casc.ErrNotSupported
	}

	in = in[1:]
	if len(in) < keyNameSize+1 {
		return nil, casc.ErrFileCorrupt
	}

	var keyName uint64
	if keyNameSize == 8 {
		keyName = binary.LittleEndian.Uint64(in[:8])
	}

	in = in[keyNameSize:]

	ivSize := int(in[0])
	if ivSize != 4 && ivSize != 8 {
		return nil, casc.ErrNotSupported
	}

	in = in[1:]
	if len(in) < ivSize+1 {
		return nil, casc.ErrFileCorrupt
	}

	var iv [16]byte // big enough for AES; Salsa20 uses 8.
	copy(iv[:], in[:ivSize])
	in = in[ivSize:]

	encType := in[0]
	in = in[1:]

	// XOR IV with frame index (low bytes first).
	for i := 0; i < 4; i++ {
		iv[i] ^= byte(frameIndex >> uint(i*8))
	}

	key := r.Find(keyName)
	if key == nil {
		return nil, fmt.Errorf("%w: KeyName=%016x", casc.ErrEncrypted, keyName)
	}

	out := make([]byte, len(in))

	switch encType {
	case 'S':
		salsa20XOR(out, in, key, iv[:8])
		return out, nil
	case 'A':
		// AES-128-CTR. The 16-byte IV: first ivSize bytes from the file
		// (XORed with frame index), zero-padded.
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}

		stream := cipher.NewCTR(block, iv[:16])
		stream.XORKeyStream(out, in)

		return out, nil
	default:
		return nil, fmt.Errorf("%w: encryption type %q", casc.ErrNotSupported, encType)
	}
}
