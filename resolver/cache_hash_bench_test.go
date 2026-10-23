package resolver

import (
	"encoding/binary"
	"testing"

	"github.com/cespare/xxhash/v2"
	"github.com/nextdns/nextdns/resolver/query"
)

var cacheKeyHashSink uint64

// BenchmarkCacheKeyHashXXHash compares the PR's current single-shot xxhash
// implementation with the prior incremental hasher path. Both hash exactly
// the same cache-key bytes: ctx || qclass || qtype || qname.
func BenchmarkCacheKeyHashXXHash(b *testing.B) {
	cases := []struct {
		name string
		key  cacheKey
	}{
		{
			name: "DNS53",
			key: cacheKey{
				qclass: query.ClassINET,
				qtype:  query.TypeA,
				qname:  "www.example.com.",
			},
		},
		{
			name: "DoH",
			key: cacheKey{
				ctx:    "https://dns.nextdns.io/abcdef",
				qclass: query.ClassINET,
				qtype:  query.TypeA,
				qname:  "www.example.com.",
			},
		},
	}

	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			b.Run("Current_Sum64", func(b *testing.B) {
				b.ReportAllocs()
				var sum uint64
				for i := 0; i < b.N; i++ {
					sum = tc.key.hashWith(CacheHashXXHash)
				}
				cacheKeyHashSink = sum
			})
			b.Run("Incremental_New_Write", func(b *testing.B) {
				b.ReportAllocs()
				var sum uint64
				for i := 0; i < b.N; i++ {
					sum = hashCacheKeyIncremental(tc.key)
				}
				cacheKeyHashSink = sum
			})
		})
	}
}

// hashCacheKeyIncremental reproduces the previous xxhash.New/Write sequence,
// for comparison with the current stack-buffer + xxhash.Sum64 implementation.
func hashCacheKeyIncremental(k cacheKey) uint64 {
	d := xxhash.New()
	_, _ = d.Write([]byte(k.ctx))
	var fields [4]byte
	binary.BigEndian.PutUint16(fields[0:2], uint16(k.qclass))
	binary.BigEndian.PutUint16(fields[2:4], uint16(k.qtype))
	_, _ = d.Write(fields[:])
	_, _ = d.Write([]byte(k.qname))
	return d.Sum64()
}

// BenchmarkXXHashStringOnly measures Sum64String on a DNS name in isolation.
// It is a primitive-cost reference, not an equivalent cache-key hash: it omits
// ctx, qclass and qtype, so its result cannot replace cacheKey.Hash directly.
func BenchmarkXXHashStringOnly(b *testing.B) {
	const qname = "www.example.com."
	b.ReportAllocs()
	var sum uint64
	for i := 0; i < b.N; i++ {
		sum = xxhash.Sum64String(qname)
	}
	cacheKeyHashSink = sum
}
