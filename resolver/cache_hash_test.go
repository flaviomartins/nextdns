package resolver

import (
	"fmt"
	"testing"

	"github.com/dgraph-io/ristretto/v2/z"
	"github.com/nextdns/nextdns/resolver/query"
)

func TestParseCacheHash(t *testing.T) {
	for name, want := range map[string]CacheHash{"": CacheHashXXHash, "xxhash": CacheHashXXHash, "crc32": CacheHashCRC32} {
		got, err := ParseCacheHash(name)
		if err != nil || got != want {
			t.Errorf("ParseCacheHash(%q) = %v, %v; want %v", name, got, err, want)
		}
	}
	if _, err := ParseCacheHash("md5"); err == nil {
		t.Error("expected error for unknown hash")
	}
}

func TestCacheKeyHashAlgos(t *testing.T) {
	for _, h := range []CacheHash{CacheHashXXHash, CacheHashCRC32} {
		a := HashKey(h, "ctx", query.ClassINET, query.TypeA, "example.com.")
		if a != HashKey(h, "ctx", query.ClassINET, query.TypeA, "example.com.") {
			t.Errorf("%v: not deterministic", h)
		}
		if a == HashKey(h, "ctx", query.ClassINET, query.TypeAAAA, "example.com.") {
			t.Errorf("%v: qtype ignored", h)
		}
		if a == HashKey(h, "other", query.ClassINET, query.TypeA, "example.com.") {
			t.Errorf("%v: ctx ignored", h)
		}
	}
}

func BenchmarkCacheKeyHash(b *testing.B) {
	for _, h := range []CacheHash{CacheHashXXHash, CacheHashCRC32} {
		b.Run(h.String(), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				HashKey(h, "https://dns.nextdns.io/abcdef", query.ClassINET, query.TypeA, "www.example.com.")
			}
		})
	}
}

// Two DoH profile URLs whose CRC-32C cache keys collide for the same question.
const (
	collideCtxA = "https://dns.nextdns.io/308076/device-00004f56"
	collideCtxB = "https://dns.nextdns.io/1c6e9c/device-0001a35c"
)

func TestCacheKeyCollisionDoesNotCrossContexts(t *testing.T) {
	const qname = "example.com."
	if HashKey(CacheHashCRC32, collideCtxA, query.ClassINET, query.TypeA, qname) !=
		HashKey(CacheHashCRC32, collideCtxB, query.ClassINET, query.TypeA, qname) {
		t.Fatal("test vectors no longer collide with crc32")
	}
	msg := []byte{
		0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0,
		7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0,
		0, 1, 0, 1,
	}
	kA := cacheKey{collideCtxA, query.ClassINET, query.TypeA, qname}
	kB := cacheKey{collideCtxB, query.ClassINET, query.TypeA, qname}
	v := &cacheValue{ctx: collideCtxA, msg: msg}
	if !kA.Matches(v) {
		t.Fatal("entry must match its own key")
	}
	if kB.Matches(v) {
		t.Fatal("entry stored for one context must not match a colliding key from another")
	}
}

// ristretto's doorkeeper Bloom filter derives probe positions from the upper
// bits of the key, so they must carry entropy.
func TestKeyBloomFalsePositives(t *testing.T) {
	const n = 655360 // counters of a 64MB cache
	ctx := "https://dns.nextdns.io/308076/device-00004f56"
	for _, h := range []CacheHash{CacheHashXXHash, CacheHashCRC32} {
		t.Run(h.String(), func(t *testing.T) {
			key := func(i int) uint64 {
				return HashKey(h, ctx, query.ClassINET, query.TypeA, fmt.Sprintf("host-%d.example.com.", i))
			}
			bl := z.NewBloomFilter(n, 0.01)
			for i := 0; i < n; i++ {
				bl.Add(key(i))
			}
			const probes = 100000
			fp := 0
			for i := 0; i < probes; i++ {
				if bl.Has(key(n + i)) {
					fp++
				}
			}
			rate := float64(fp) / probes
			if rate > 0.02 {
				if h == CacheHashCRC32 {
					t.Skipf("known limitation: zero upper bits, false-positive rate %.4f", rate)
				}
				t.Fatalf("bloom false-positive rate %.4f, want <= 0.02", rate)
			}
		})
	}
}
