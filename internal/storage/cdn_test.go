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
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ldmonster/go-casclib/internal/casc"
	"github.com/ldmonster/go-casclib/internal/cdn"
	"github.com/ldmonster/go-casclib/internal/decrypt"
)

// buildSimpleBLTE wraps payload in a single-frame 'N' BLTE blob (with the
// 30-byte encoded-header prefix that data.NNN spans carry).
func buildSimpleBLTE(payload []byte) []byte {
	encoded := append([]byte{'N'}, payload...)
	hash := md5.Sum(encoded)
	const frameHdrSize = 24
	const headerSize = 12 + frameHdrSize
	var blte bytes.Buffer
	blte.Write([]byte{'B', 'L', 'T', 'E'})
	hs := make([]byte, 4)
	binary.BigEndian.PutUint32(hs, headerSize)
	blte.Write(hs)
	blte.WriteByte(0x0F)
	blte.Write([]byte{0, 0, 1})
	enc := make([]byte, 4)
	binary.BigEndian.PutUint32(enc, uint32(len(encoded)))
	cont := make([]byte, 4)
	binary.BigEndian.PutUint32(cont, uint32(len(payload)))
	blte.Write(enc)
	blte.Write(cont)
	blte.Write(hash[:])
	blte.Write(encoded)

	const encHdr = 30
	out := make([]byte, encHdr+blte.Len())
	copy(out[encHdr:], blte.Bytes())
	return out
}

// TestReadByEKeyCDNFallback drives the online fallback path: the storage
// has no local indexes containing the requested EKey, but the CDN.Client
// is wired to an httptest server that serves the right blob.
func TestReadByEKeyCDNFallback(t *testing.T) {
	payload := []byte("hello-from-cdn")
	var ek casc.EKey
	for i := range ek {
		ek[i] = byte(i + 1)
	}
	hexKey := hex.EncodeToString(ek[:])

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// expected URL: /tpr/wow/data/<aa>/<bb>/<full>
		want := "/tpr/wow/data/" + hexKey[0:2] + "/" + hexKey[2:4] + "/" + hexKey
		if r.URL.Path != want {
			t.Errorf("unexpected CDN path: got %q, want %q", r.URL.Path, want)
			http.NotFound(w, r)
			return
		}
		w.Write(buildSimpleBLTE(payload))
	}))
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "http://")
	s := &Storage{
		CDN:  cdn.NewClient([]string{host}, "tpr/wow"),
		Keys: decrypt.NewKeyRegistry(),
	}

	got, err := s.ReadByEKey(ek)
	if err != nil {
		t.Fatalf("ReadByEKey: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("got %q, want %q", got, payload)
	}
}

// TestReadByEKeyCDNDisabledWithoutOnline asserts that an unknown EKey
// returns ErrFileNotFound when no CDN client is configured.
func TestReadByEKeyCDNDisabledWithoutOnline(t *testing.T) {
	s := &Storage{
		Keys: decrypt.NewKeyRegistry(),
	}
	var ek casc.EKey
	if _, err := s.ReadByEKey(ek); err == nil {
		t.Error("expected ErrFileNotFound when no CDN and no local match")
	}
}
