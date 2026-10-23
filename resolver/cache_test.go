package resolver

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/nextdns/nextdns/resolver/query"
)

func Test_cacheValue_AdjustedResponse(t *testing.T) {
	type fields struct {
		time time.Time
		msg  []byte
	}
	now := time.Now()
	tests := []struct {
		name       string
		fields     fields
		id         uint16
		wantB      []byte
		wantMinTTL uint32
	}{
		{
			"Empty Record",
			fields{
				now.Add(-10 * time.Second),
				[]byte{},
			},
			123,
			[]byte{},
			0,
		},
		{
			"Happy Path",
			fields{
				now.Add(-10 * time.Second),
				[]byte{
					0xa6, 0xed, // ID
					0x81, 0x80, // Flags
					0x00, 0x01, // Questions
					0x00, 0x01, // Answers
					0x00, 0x00, // Authorities
					0x00, 0x01, // Additionals
					// Questions
					0x04, 0x74, 0x65, 0x73, 0x74, 0x03, 0x63, 0x6f, 0x6d, 0x00, // Label test.com.
					0x00, 0x01, // Type A
					0x00, 0x01, // Class IN
					// Answers
					0xc0, 0x0c, // Label pointer test.com.
					0x00, 0x01, // Type A
					0x00, 0x01, // Class IN
					0x00, 0x00, 0x0e, 0x10, // TTL 3600
					0x00, 0x04, // Data len 4
					0x45, 0xac, 0xc8, 0xeb, // 69.172.200.
					// Additionals
					0x00,       // Label <root>
					0x00, 0x29, // Type OPT
					0x05, 0xac, // UDP packet size
					0x00,       // Extended RCODE
					0x00,       // EDNS Version
					0x00, 0x00, // Flags
					0x00, 0x00, // DATA
				},
			},
			123,
			[]byte{
				0x00, 0x7b, // ID = 123
				0x81, 0x80, // Flags
				0x00, 0x01, // Questions
				0x00, 0x01, // Answers
				0x00, 0x00, // Authorities
				0x00, 0x01, // Additionals
				// Questions
				0x04, 0x74, 0x65, 0x73, 0x74, 0x03, 0x63, 0x6f, 0x6d, 0x00, // Label test.com.
				0x00, 0x01, // Type A
				0x00, 0x01, // Class IN
				// Answers
				0xc0, 0x0c, // Label pointer test.com.
				0x00, 0x01, // Type A
				0x00, 0x01, // Class IN
				0x00, 0x00, 0x0e, 0x06, // TTL 3600 - 10
				0x00, 0x04, // Data len 4
				0x45, 0xac, 0xc8, 0xeb, // 69.172.200.235
				// Additionals
				0x00,       // Label <root>
				0x00, 0x29, // Type OPT
				0x05, 0xac, // UDP packet size
				0x00,       // Extended RCODE
				0x00,       // EDNS Version
				0x00, 0x00, // Flags
				0x00, 0x00, // DATA
			},
			3600 - 10,
		},
		// TODO: fuzz
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := cacheValue{
				time: tt.fields.time,
				msg:  tt.fields.msg,
			}
			buf := make([]byte, 4096)
			n, gotMinTTL := v.AdjustedResponse(buf, tt.id, 0, 0, now)
			if gotB := buf[:n]; !reflect.DeepEqual(gotB, tt.wantB) {
				t.Errorf("cacheValue.AdjustedResponse()\ngotB:\n%#v\nwant:\n%#v", gotB, tt.wantB)
			}
			if gotMinTTL != tt.wantMinTTL {
				t.Errorf("cacheValue.AdjustedResponse() gotMinTTL = %v, want %v", gotMinTTL, tt.wantMinTTL)
			}
		})
	}
}

func Test_cacheKey_ValidateQuestion(t *testing.T) {
	msg := []byte{
		0x00, 0x01, // ID
		0x01, 0x00, // Flags (RD)
		0x00, 0x01, // Questions
		0x00, 0x00, // Answers
		0x00, 0x00, // Authorities
		0x00, 0x00, // Additionals
		// Question: test.com. A IN
		0x04, 0x74, 0x65, 0x73, 0x74, 0x03, 0x63, 0x6f, 0x6d, 0x00,
		0x00, 0x01, // Type A
		0x00, 0x01, // Class IN
	}
	k := cacheKey{"", query.ClassINET, query.TypeA, "test.com."}
	if !k.ValidateQuestion(msg) {
		t.Fatalf("expected ValidateQuestion to be true")
	}
	k2 := cacheKey{"", query.ClassINET, query.TypeAAAA, "test.com."}
	if k2.ValidateQuestion(msg) {
		t.Fatalf("expected ValidateQuestion to be false")
	}
}

var cacheHashBenchNames = []string{
	"t.co.", "x.com.", "fb.com.", "bit.ly.", "ft.com.",
	"google.com.", "apple.com.", "amazon.com.", "netflix.com.", "github.com.",
	"www.google.com.", "www.youtube.com.", "api.github.com.", "mail.yahoo.com.",
	"login.microsoftonline.com.", "play.googleapis.com.", "cdn.jsdelivr.net.",
	"graph.facebook.com.", "clients4.google.com.", "ocsp.digicert.com.",
	"time.cloudflare.com.", "update.googleapis.com.", "static.xx.fbcdn.net.",
	"d1234abcd5efgh.cloudfront.net.", "e1234.dscb.akamaiedge.net.",
	"safebrowsing.googleapis.com.", "gateway.icloud.com.akadns.net.",
	"android.clients.google.com.", "settings-win.data.microsoft.com.",
	"s3-us-west-2.amazonaws.com.", "ec2-54-12-34-56.compute-1.amazonaws.com.",
	"prod-eu-west-1-lb-1234567890.elb.eu-west-1.amazonaws.com.",
	"a248.e.akamai.net.", "scontent-lhr8-1.xx.fbcdn.net.",
	"pagead2.googlesyndication.com.", "securepubads.g.doubleclick.net.",
	"device-metrics-us-2.amazon.com.", "mobile.events.data.microsoft.com.",
	"v10.events.data.microsoft.com.", "self.events.data.microsoft.com.",
	"east-us-2.prod.telemetry.example-corp.co.uk.",
	"4d1b5c2e-9f3a-4b7e-8c1d-2a6f0e9b7d34.tracking.some-analytics-vendor.com.",
	"_dns.resolver.arpa.", "_acme-challenge.home.example.org.",
	"1.0.0.127.in-addr.arpa.", "very-long-subdomain.cdn.region.provider.example.co.uk.",
}

var cacheHashBenchSink uint64

func BenchmarkCacheKeyHash(b *testing.B) {
	const doh = "https://dns.nextdns.io/abcdef"
	longName := strings.Repeat(strings.Repeat("a", 63)+".", 3) + strings.Repeat("b", 61) + "."
	for _, tc := range []struct {
		name     string
		contexts []string
		names    []string
	}{
		{"DNS53", []string{""}, cacheHashBenchNames},
		{"DoH", []string{doh}, cacheHashBenchNames},
		{"Mixed", []string{"", doh}, cacheHashBenchNames},
		{"ShortDNS53", []string{""}, []string{"www.example.com."}},
		{"ShortDoH", []string{doh}, []string{"www.example.com."}},
		{"Key255", []string{doh}, []string{longName[:255-len(doh)-4-1] + "."}},
		{"Key256", []string{doh}, []string{longName[:256-len(doh)-4-1] + "."}},
		{"Key257", []string{doh}, []string{longName[:257-len(doh)-4-1] + "."}},
		{"LongName", []string{doh}, []string{longName}},
		{"LongContext", []string{doh + "/" + strings.Repeat("device", 50)}, cacheHashBenchNames},
	} {
		b.Run(tc.name, func(b *testing.B) {
			var keys []cacheKey
			for _, name := range tc.names {
				for _, ctx := range tc.contexts {
					for _, qtype := range []query.Type{query.TypeA, query.TypeAAAA} {
						keys = append(keys, cacheKey{ctx, query.ClassINET, qtype, name})
					}
				}
			}
			b.ReportAllocs()
			var sum uint64
			i := 0
			for b.Loop() {
				sum ^= keys[i].Hash()
				i++
				if i == len(keys) {
					i = 0
				}
			}
			cacheHashBenchSink = sum
		})
	}
}
