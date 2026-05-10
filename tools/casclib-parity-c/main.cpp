// casclib-parity-c is the native C++ implementation of the go-casclib
// parity contract. It links against the vendored upstream CascLib and
// emits the same JSONL protocol as tools/paritycmd (the Go binary).
//
// Subcommands:
//   capabilities
//   info <storage-dir>
//   list <storage-dir> [pattern]
//   read <storage-dir> <filename>
//
// Match notes:
//   * `list` walks via CascFindFirstFile / CascFindNextFile and emits one
//     JSON object per file with the same keys as the Go binary.
//   * `read` reads the entire file (CascReadFile until EOF), SHA-256s it,
//     and emits the same {name,size,sha256,hex_first_bytes} record.
//
// Dependencies:
//   * CascLib (vendored at ../../CascLib).
//   * No external SHA-256: a small public-domain implementation is bundled
//     below to avoid pulling in OpenSSL.

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <fnmatch.h>

#include "CascLib.h"

namespace {

// ---------------------------------------------------------------------
// Minimal SHA-256 (public-domain, B. Conrad / Brad Conte style). Used to
// avoid an OpenSSL/libcrypto dependency for the parity binary.
struct sha256_ctx {
    uint32_t state[8];
    uint64_t bitlen;
    uint32_t datalen;
    uint8_t  data[64];
};
static const uint32_t kK[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
};
static inline uint32_t rotr(uint32_t a, uint32_t b) { return (a>>b)|(a<<(32-b)); }
static void sha256_transform(sha256_ctx* c, const uint8_t* data) {
    uint32_t a,b,e,f,g,h,t1,t2,m[64];
    for (int i=0,j=0; i<16; i++,j+=4)
        m[i]=(data[j]<<24)|(data[j+1]<<16)|(data[j+2]<<8)|data[j+3];
    for (int i=16; i<64; i++) {
        uint32_t s0=rotr(m[i-15],7)^rotr(m[i-15],18)^(m[i-15]>>3);
        uint32_t s1=rotr(m[i-2],17)^rotr(m[i-2],19)^(m[i-2]>>10);
        m[i]=m[i-16]+s0+m[i-7]+s1;
    }
    a=c->state[0]; b=c->state[1]; uint32_t cc=c->state[2]; uint32_t d=c->state[3];
    e=c->state[4]; f=c->state[5]; g=c->state[6]; h=c->state[7];
    for (int i=0; i<64; i++) {
        t1=h+(rotr(e,6)^rotr(e,11)^rotr(e,25))+((e&f)^(~e&g))+kK[i]+m[i];
        t2=(rotr(a,2)^rotr(a,13)^rotr(a,22))+((a&b)^(a&cc)^(b&cc));
        h=g; g=f; f=e; e=d+t1; d=cc; cc=b; b=a; a=t1+t2;
    }
    c->state[0]+=a; c->state[1]+=b; c->state[2]+=cc; c->state[3]+=d;
    c->state[4]+=e; c->state[5]+=f; c->state[6]+=g; c->state[7]+=h;
}
static void sha256_init(sha256_ctx* c) {
    c->datalen=0; c->bitlen=0;
    c->state[0]=0x6a09e667; c->state[1]=0xbb67ae85; c->state[2]=0x3c6ef372; c->state[3]=0xa54ff53a;
    c->state[4]=0x510e527f; c->state[5]=0x9b05688c; c->state[6]=0x1f83d9ab; c->state[7]=0x5be0cd19;
}
static void sha256_update(sha256_ctx* c, const uint8_t* p, size_t n) {
    for (size_t i=0; i<n; i++) {
        c->data[c->datalen++]=p[i];
        if (c->datalen==64) { sha256_transform(c,c->data); c->bitlen+=512; c->datalen=0; }
    }
}
static void sha256_final(sha256_ctx* c, uint8_t out[32]) {
    uint32_t i=c->datalen;
    if (i<56) { c->data[i++]=0x80; while (i<56) c->data[i++]=0; }
    else { c->data[i++]=0x80; while (i<64) c->data[i++]=0; sha256_transform(c,c->data); memset(c->data,0,56); }
    c->bitlen+=c->datalen*8;
    for (int j=0; j<8; j++) c->data[63-j]=(uint8_t)(c->bitlen>>(8*j));
    sha256_transform(c,c->data);
    for (int j=0; j<4; j++) for (int k=0; k<8; k++) out[j+k*4]=(uint8_t)(c->state[k]>>(24-j*8));
}

std::string hex_of(const uint8_t* p, size_t n) {
    static const char d[]="0123456789abcdef";
    std::string s; s.resize(n*2);
    for (size_t i=0; i<n; i++) { s[2*i]=d[p[i]>>4]; s[2*i+1]=d[p[i]&0xF]; }
    return s;
}

std::string json_escape(const std::string& s) {
    std::string o; o.reserve(s.size()+2);
    o.push_back('"');
    for (char c : s) {
        switch (c) {
            case '"':  o += "\\\""; break;
            case '\\': o += "\\\\"; break;
            case '\b': o += "\\b"; break;
            case '\f': o += "\\f"; break;
            case '\n': o += "\\n"; break;
            case '\r': o += "\\r"; break;
            case '\t': o += "\\t"; break;
            default:
                if ((unsigned char)c < 0x20) {
                    char buf[8]; std::snprintf(buf, sizeof(buf), "\\u%04x", (unsigned char)c);
                    o += buf;
                } else {
                    o.push_back(c);
                }
        }
    }
    o.push_back('"');
    return o;
}

// ---------------------------------------------------------------------

int print_capabilities() {
    std::cout << "{"
              << json_escape("impl") << ":" << json_escape("casclib-c") << ","
              << json_escape("version") << ":" << json_escape("0.1.0") << ","
              << json_escape("protocol") << ":" << json_escape("v0.1.0") << ","
              << json_escape("subcommands") << ":[\"capabilities\",\"info\",\"list\",\"read\"],"
              << json_escape("supports_glob") << ":true,"
              << json_escape("supports_read") << ":true,"
              << json_escape("online_capable") << ":false"
              << "}\n";
    return 0;
}

bool open_storage(const char* dir, HANDLE* out) {
    if (!CascOpenStorage(dir, 0, out)) {
        std::fprintf(stderr, "casclib-parity-c: CascOpenStorage(%s) failed: %u\n", dir, GetCascError());
        return false;
    }
    return true;
}

int cmd_info(const char* dir) {
    HANDLE hs;
    if (!open_storage(dir, &hs)) return 2;
    size_t count = 0;
    CASC_FIND_DATA fd; std::memset(&fd, 0, sizeof(fd));
    HANDLE find = CascFindFirstFile(hs, "*", &fd, NULL);
    if (find != INVALID_HANDLE_VALUE) {
        do { count++; } while (CascFindNextFile(find, &fd));
        CascFindClose(find);
    }

    // Probe a few well-known CASC_STORAGE_INFO_CLASS fields. These are
    // best-effort: missing fields just stay blank.
    CASC_STORAGE_PRODUCT prod = {};
    size_t got = 0;
    CascGetStorageInfo(hs, CascStorageProduct, &prod, sizeof(prod), &got);

    std::cout << "{"
              << json_escape("impl") << ":" << json_escape("casclib-c") << ","
              << json_escape("file_count") << ":" << count << ","
              << json_escape("dir") << ":" << json_escape(dir) << ","
              << json_escape("product") << ":" << json_escape(prod.szCodeName) << ","
              << json_escape("build_number") << ":" << prod.BuildNumber
              << "}\n";
    CascCloseStorage(hs);
    return 0;
}

int cmd_list(const char* dir, const char* pattern) {
    HANDLE hs;
    if (!open_storage(dir, &hs)) return 2;
    CASC_FIND_DATA fd; std::memset(&fd, 0, sizeof(fd));
    HANDLE find = CascFindFirstFile(hs, "*", &fd, NULL);
    if (find == INVALID_HANDLE_VALUE) { CascCloseStorage(hs); return 0; }
    do {
        if (pattern && *pattern) {
            if (fnmatch(pattern, fd.szFileName, FNM_CASEFOLD) != 0) continue;
        }
        std::cout << "{"
                  << json_escape("name") << ":" << json_escape(fd.szFileName) << ","
                  << json_escape("ckey") << ":" << json_escape(hex_of(fd.CKey, 16)) << ","
                  << json_escape("ekey") << ":" << json_escape(hex_of(fd.EKey, 16)) << ","
                  << json_escape("content_size") << ":" << fd.FileSize << ","
                  << json_escape("encoded_size") << ":" << fd.FileSize << ","
                  << json_escape("file_data_id") << ":" << fd.dwFileDataId
                  << "}\n";
    } while (CascFindNextFile(find, &fd));
    CascFindClose(find);
    CascCloseStorage(hs);
    return 0;
}

int cmd_read(const char* dir, const char* name) {
    HANDLE hs;
    if (!open_storage(dir, &hs)) return 2;
    HANDLE hf;
    if (!CascOpenFile(hs, name, 0, 0, &hf)) {
        std::fprintf(stderr, "casclib-parity-c: CascOpenFile(%s) failed: %u\n", name, GetCascError());
        CascCloseStorage(hs);
        return 2;
    }
    sha256_ctx ctx; sha256_init(&ctx);
    std::vector<uint8_t> head; head.reserve(64);
    std::vector<uint8_t> buf(64 * 1024);
    uint64_t total = 0;
    DWORD got = 0;
    while (CascReadFile(hf, buf.data(), (DWORD)buf.size(), &got) && got > 0) {
        if (head.size() < 64) {
            size_t want = std::min<size_t>(64 - head.size(), got);
            head.insert(head.end(), buf.begin(), buf.begin() + want);
        }
        sha256_update(&ctx, buf.data(), got);
        total += got;
    }
    uint8_t digest[32];
    sha256_final(&ctx, digest);
    std::cout << "{"
              << json_escape("name") << ":" << json_escape(name) << ","
              << json_escape("size") << ":" << total << ","
              << json_escape("sha256") << ":" << json_escape(hex_of(digest, 32)) << ","
              << json_escape("hex_first_bytes") << ":" << json_escape(hex_of(head.data(), head.size()))
              << "}\n";
    CascCloseFile(hf);
    CascCloseStorage(hs);
    return 0;
}

} // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        std::fprintf(stderr, "usage: casclib-parity-c <capabilities|info|list|read> ...\n");
        return 1;
    }
    std::string cmd = argv[1];
    if (cmd == "capabilities") return print_capabilities();
    if (cmd == "info") {
        if (argc < 3) { std::fprintf(stderr, "usage: casclib-parity-c info <storage-dir>\n"); return 1; }
        return cmd_info(argv[2]);
    }
    if (cmd == "list") {
        if (argc < 3) { std::fprintf(stderr, "usage: casclib-parity-c list <storage-dir> [pattern]\n"); return 1; }
        return cmd_list(argv[2], argc >= 4 ? argv[3] : "");
    }
    if (cmd == "read") {
        if (argc < 4) { std::fprintf(stderr, "usage: casclib-parity-c read <storage-dir> <filename>\n"); return 1; }
        return cmd_read(argv[2], argv[3]);
    }
    std::fprintf(stderr, "unknown subcommand: %s\n", cmd.c_str());
    return 1;
}
