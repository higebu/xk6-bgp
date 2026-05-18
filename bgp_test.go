package bgp

import (
	"fmt"
	"strings"
	"testing"

	"github.com/grafana/sobek"
	gobgp "github.com/osrg/gobgp/v4/pkg/packet/bgp"

	"github.com/higebu/xk6-bgp/internal/packet"
)

func newRT(t testing.TB) *sobek.Runtime {
	t.Helper()
	return sobek.New()
}

func evalArray(t testing.TB, rt *sobek.Runtime, src string) sobek.Value {
	t.Helper()
	v, err := rt.RunString(src)
	if err != nil {
		t.Fatalf("eval %q: %v", src, err)
	}
	return v
}

// ipPrefix extracts the prefix from a packet.Route, asserting it is an
// IPRoute. Use only in tests that construct IP unicast routes.
func ipPrefix(t testing.TB, r packet.Route) string {
	t.Helper()
	ipr, ok := r.(packet.IPRoute)
	if !ok {
		t.Fatalf("expected packet.IPRoute, got %T", r)
	}
	return ipr.Prefix().String()
}

func TestParseRoutesArray_StringForm(t *testing.T) {
	rt := newRT(t)
	// Family-mixed inputs require two passes: parseRoutesArray takes a
	// single family per call.
	arr4 := evalArray(t, rt, `["10.0.0.0/24", "10.0.1.0/24"]`)
	got4, err := parseRoutesArray(rt, gobgp.RF_IPv4_UC, arr4)
	if err != nil {
		t.Fatalf("parseRoutesArray v4: %v", err)
	}
	wantV4 := []string{"10.0.0.0/24", "10.0.1.0/24"}
	if len(got4) != len(wantV4) {
		t.Fatalf("v4 len=%d, want %d", len(got4), len(wantV4))
	}
	for i, want := range wantV4 {
		if p := ipPrefix(t, got4[i]); p != want {
			t.Errorf("v4 routes[%d]=%s, want %s", i, p, want)
		}
	}

	arr6 := evalArray(t, rt, `["2001:db8::/32"]`)
	got6, err := parseRoutesArray(rt, gobgp.RF_IPv6_UC, arr6)
	if err != nil {
		t.Fatalf("parseRoutesArray v6: %v", err)
	}
	if len(got6) != 1 {
		t.Fatalf("v6 len=%d, want 1", len(got6))
	}
	if p := ipPrefix(t, got6[0]); p != "2001:db8::/32" {
		t.Errorf("v6 routes[0]=%s, want 2001:db8::/32", p)
	}
}

func TestParseRoutesArray_ObjectForm(t *testing.T) {
	rt := newRT(t)
	arr := evalArray(t, rt, `[
		{prefix: "10.0.0.0/24"},
		{prefix: "10.0.1.0/24"}
	]`)
	got, err := parseRoutesArray(rt, gobgp.RF_IPv4_UC, arr)
	if err != nil {
		t.Fatalf("parseRoutesArray: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("len=%d, want 2", len(got))
	}
	if p := ipPrefix(t, got[0]); p != "10.0.0.0/24" {
		t.Errorf("got[0]=%s, want 10.0.0.0/24", p)
	}
}

func TestParseRoutesArray_Errors(t *testing.T) {
	rt := newRT(t)
	cases := []struct {
		name string
		src  string
		want string
	}{
		{"empty", `[]`, "non-empty"},
		{"badPrefixStr", `["not-a-prefix"]`, "routes[0]"},
		{"badPrefixObj", `[{prefix: "nope"}]`, "routes[0]"},
		{"missingPrefix", `[{}]`, "missing prefix"},
		{"nullEntry", `[null]`, "routes[0]"},
		{"numberEntry", `[42]`, "routes[0]"},
		{"familyMismatch", `["2001:db8::/32"]`, "does not match"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			arr := evalArray(t, rt, tc.src)
			_, err := parseRoutesArray(rt, gobgp.RF_IPv4_UC, arr)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not contain %q", err.Error(), tc.want)
			}
		})
	}
}

func TestParseRoutesArray_LargeStringList(t *testing.T) {
	// Exercise the hot path: large COUNT, string-only entries, no
	// per-element heap detours through Export()'s []any path.
	const n = 5000
	rt := newRT(t)
	var sb strings.Builder
	sb.Grow(n * 18)
	sb.WriteByte('[')
	for i := range n {
		if i > 0 {
			sb.WriteByte(',')
		}
		fmt.Fprintf(&sb, `"10.%d.%d.%d/32"`, (i>>16)&0xff, (i>>8)&0xff, i&0xff)
	}
	sb.WriteByte(']')
	arr := evalArray(t, rt, sb.String())
	got, err := parseRoutesArray(rt, gobgp.RF_IPv4_UC, arr)
	if err != nil {
		t.Fatalf("parseRoutesArray: %v", err)
	}
	if len(got) != n {
		t.Fatalf("len=%d, want %d", len(got), n)
	}
	// Spot-check the first and last entry.
	if p := ipPrefix(t, got[0]); p != "10.0.0.0/32" {
		t.Errorf("got[0]=%s, want 10.0.0.0/32", p)
	}
	want := fmt.Sprintf("10.%d.%d.%d/32", ((n-1)>>16)&0xff, ((n-1)>>8)&0xff, (n-1)&0xff)
	if p := ipPrefix(t, got[n-1]); p != want {
		t.Errorf("got[last]=%s, want %s", p, want)
	}
}

func TestParsePrefixList_Roundtrip(t *testing.T) {
	rt := newRT(t)
	obj := rt.NewObject()
	arr, err := rt.RunString(`["2001:0db8::/32", "10.0.0.0/24"]`)
	if err != nil {
		t.Fatalf("eval array: %v", err)
	}
	if err := obj.Set("prefixes", arr); err != nil {
		t.Fatalf("set prefixes: %v", err)
	}
	got, err := parsePrefixList(rt, obj)
	if err != nil {
		t.Fatalf("parsePrefixList: %v", err)
	}
	want := []string{"2001:db8::/32", "10.0.0.0/24"}
	if len(got) != len(want) {
		t.Fatalf("len=%d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("got[%d]=%s, want %s", i, got[i], want[i])
		}
	}
}

func TestParsePrefixList_Errors(t *testing.T) {
	rt := newRT(t)
	cases := []struct {
		name  string
		setup func() *sobek.Object
		want  string
	}{
		{
			name: "missing",
			setup: func() *sobek.Object {
				return rt.NewObject()
			},
			want: "prefixes is required",
		},
		{
			name: "empty",
			setup: func() *sobek.Object {
				o := rt.NewObject()
				v, _ := rt.RunString(`[]`)
				_ = o.Set("prefixes", v)
				return o
			},
			want: "non-empty",
		},
		{
			name: "numberEntry",
			setup: func() *sobek.Object {
				o := rt.NewObject()
				v, _ := rt.RunString(`[123]`)
				_ = o.Set("prefixes", v)
				return o
			},
			want: "descriptor must carry either",
		},
		{
			name: "badPrefix",
			setup: func() *sobek.Object {
				o := rt.NewObject()
				v, _ := rt.RunString(`["not-a-prefix"]`)
				_ = o.Set("prefixes", v)
				return o
			},
			want: "prefixes[0]",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parsePrefixList(rt, tc.setup())
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not contain %q", err.Error(), tc.want)
			}
		})
	}
}

func TestParseRoutesArray_MUP(t *testing.T) {
	rt := newRT(t)
	arr := evalArray(t, rt, `[
		{ type: 'isd',  rd: '65000:1', prefix: '10.10.10.0/24' },
		{ type: 'dsd',  rd: '65000:1', address: '10.10.10.1' },
		{ type: 't1st', rd: '65000:1', prefix: '192.0.2.0/24', teid: '0.0.0.100', qfi: 9, endpoint: '10.10.10.1' },
		{ type: 't1st', rd: '65000:1', prefix: '192.0.2.0/24', teid: '0.0.0.100', qfi: 9, endpoint: '10.10.10.1', source: '10.10.10.2' },
		{ type: 't2st', rd: '65000:1', endpoint: '10.10.10.1', endpointAddressLength: 64, teid: '0.0.0.100' }
	]`)
	got, err := parseRoutesArray(rt, gobgp.RF_MUP_IPv4, arr)
	if err != nil {
		t.Fatalf("parseRoutesArray: %v", err)
	}
	if len(got) != 5 {
		t.Fatalf("len=%d, want 5", len(got))
	}
	wantKeys := []string{
		"[type:isd][rd:65000:1][prefix:10.10.10.0/24]",
		"[type:dsd][rd:65000:1][prefix:10.10.10.1]",
		"[type:t1st][rd:65000:1][prefix:192.0.2.0/24]",
		"[type:t1st][rd:65000:1][prefix:192.0.2.0/24]",
		"[type:t2st][rd:65000:1][endpoint-address-length:64][endpoint:10.10.10.1][teid:0.0.0.100]",
	}
	for i, want := range wantKeys {
		mr, ok := got[i].(packet.MUPRoute)
		if !ok {
			t.Fatalf("routes[%d] is %T, want MUPRoute", i, got[i])
		}
		if mr.Key() != want {
			t.Errorf("routes[%d].Key=%s, want %s", i, mr.Key(), want)
		}
	}
}

func TestParseRoutesArray_MUPErrors(t *testing.T) {
	rt := newRT(t)
	cases := []struct {
		name string
		src  string
		want string
	}{
		{"bareStringNotAllowed", `["10.0.0.0/24"]`, "must be an object"},
		{"missingType", `[{ rd: '65000:1', prefix: '10.0.0.0/24' }]`, "missing type"},
		{"unknownType", `[{ type: 'foo', rd: '65000:1' }]`, "unknown mup route type"},
		{"missingRD", `[{ type: 'isd', prefix: '10.0.0.0/24' }]`, "missing rd"},
		{"missingPrefix", `[{ type: 'isd', rd: '65000:1' }]`, "missing prefix"},
		{"missingAddress", `[{ type: 'dsd', rd: '65000:1' }]`, "missing address"},
		{"t2stMissingEAL", `[{ type: 't2st', rd: '65000:1', endpoint: '10.0.0.1', teid: '0.0.0.1' }]`, "endpointAddressLength"},
		{"t1stIPv6TEID", `[{ type: 't1st', rd: '65000:1', prefix: '10.0.0.1/32', teid: '::1', qfi: 9, endpoint: '10.0.0.1' }]`, "teid must be an IPv4-shaped"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			arr := evalArray(t, rt, tc.src)
			_, err := parseRoutesArray(rt, gobgp.RF_MUP_IPv4, arr)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not contain %q", err.Error(), tc.want)
			}
		})
	}
}

func TestParsePrefixList_MUPDescriptors(t *testing.T) {
	rt := newRT(t)
	obj := rt.NewObject()
	arr, err := rt.RunString(`[
		{ type: 'isd', rd: '65000:1', prefix: '10.10.10.0/24' },
		{ type: 'dsd', rd: '65000:1', address: '2001:db8::1' },
		'10.0.0.0/24'
	]`)
	if err != nil {
		t.Fatalf("eval: %v", err)
	}
	if err := obj.Set("prefixes", arr); err != nil {
		t.Fatalf("set prefixes: %v", err)
	}
	got, err := parsePrefixList(rt, obj)
	if err != nil {
		t.Fatalf("parsePrefixList: %v", err)
	}
	want := []string{
		"[type:isd][rd:65000:1][prefix:10.10.10.0/24]",
		"[type:dsd][rd:65000:1][prefix:2001:db8::1]",
		"10.0.0.0/24",
	}
	if len(got) != len(want) {
		t.Fatalf("len=%d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("got[%d]=%s, want %s", i, got[i], want[i])
		}
	}
}

func TestParseRoutesArray_L3VPN(t *testing.T) {
	rt := newRT(t)
	arr := evalArray(t, rt, `[
		{ rd: '65000:1', prefix: '10.10.10.0/24' },
		{ rd: '65000:1', prefix: '10.10.11.0/24' }
	]`)
	got, err := parseRoutesArray(rt, gobgp.RF_IPv4_VPN, arr)
	if err != nil {
		t.Fatalf("parseRoutesArray: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("len=%d, want 2", len(got))
	}
	wantKeys := []string{
		"65000:1:10.10.10.0/24",
		"65000:1:10.10.11.0/24",
	}
	for i, want := range wantKeys {
		vr, ok := got[i].(packet.VPNIPRoute)
		if !ok {
			t.Fatalf("routes[%d] is %T, want VPNIPRoute", i, got[i])
		}
		if vr.Key() != want {
			t.Errorf("routes[%d].Key=%s, want %s", i, vr.Key(), want)
		}
	}

	arr6 := evalArray(t, rt, `[{ rd: '65000:1', prefix: '2001:db8:1::/48' }]`)
	got6, err := parseRoutesArray(rt, gobgp.RF_IPv6_VPN, arr6)
	if err != nil {
		t.Fatalf("parseRoutesArray v6: %v", err)
	}
	if len(got6) != 1 {
		t.Fatalf("v6 len=%d, want 1", len(got6))
	}
	vr := got6[0].(packet.VPNIPRoute)
	if vr.Key() != "65000:1:2001:db8:1::/48" {
		t.Errorf("v6 routes[0].Key=%s", vr.Key())
	}
}

func TestParseRoutesArray_L3VPNErrors(t *testing.T) {
	rt := newRT(t)
	cases := []struct {
		name string
		src  string
		want string
	}{
		{"bareStringNotAllowed", `["10.0.0.0/24"]`, "must be an object"},
		{"missingRD", `[{ prefix: '10.0.0.0/24' }]`, "missing rd"},
		{"missingPrefix", `[{ rd: '65000:1' }]`, "missing prefix"},
		{"familyMismatch", `[{ rd: '65000:1', prefix: '2001:db8::/64' }]`, "does not match"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			arr := evalArray(t, rt, tc.src)
			_, err := parseRoutesArray(rt, gobgp.RF_IPv4_VPN, arr)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not contain %q", err.Error(), tc.want)
			}
		})
	}
}

func TestParsePrefixList_L3VPNDescriptors(t *testing.T) {
	rt := newRT(t)
	obj := rt.NewObject()
	arr, err := rt.RunString(`[
		{ rd: '65000:1', prefix: '10.0.0.0/24' },
		{ rd: '65000:1', prefix: '2001:db8::/48' },
		'10.10.0.0/24'
	]`)
	if err != nil {
		t.Fatalf("eval: %v", err)
	}
	if err := obj.Set("prefixes", arr); err != nil {
		t.Fatalf("set prefixes: %v", err)
	}
	got, err := parsePrefixList(rt, obj)
	if err != nil {
		t.Fatalf("parsePrefixList: %v", err)
	}
	want := []string{
		"65000:1:10.0.0.0/24",
		"65000:1:2001:db8::/48",
		"10.10.0.0/24",
	}
	if len(got) != len(want) {
		t.Fatalf("len=%d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("got[%d]=%s, want %s", i, got[i], want[i])
		}
	}
}

func TestParseSRv6L3Service(t *testing.T) {
	rt := newRT(t)
	v, err := rt.RunString(`({
		sid: 'fc00:0:1::',
		behavior: 'END_DT4',
		structure: {
			locatorBlockLength:  40,
			locatorNodeLength:   24,
			functionLength:      16,
			argumentLength:      0,
		}
	})`)
	if err != nil {
		t.Fatalf("eval: %v", err)
	}
	cfg, err := parseSRv6L3Service(rt, v)
	if err != nil {
		t.Fatalf("parseSRv6L3Service: %v", err)
	}
	if cfg.SID.String() != "fc00:0:1::" {
		t.Errorf("sid=%s", cfg.SID)
	}
	if cfg.EndpointBehavior != gobgp.END_DT4 {
		t.Errorf("behavior=%d, want END_DT4", cfg.EndpointBehavior)
	}
	if cfg.FunctionLength != 16 {
		t.Errorf("functionLength=%d, want 16", cfg.FunctionLength)
	}
}

func TestParseSRv6L3ServiceErrors(t *testing.T) {
	rt := newRT(t)
	cases := []struct {
		name string
		src  string
		want string
	}{
		{"missingSID", `({ behavior: 'END_DT4' })`, "missing sid"},
		{"missingBehavior", `({ sid: 'fc00::1' })`, "missing behavior"},
		{"unknownBehavior", `({ sid: 'fc00::1', behavior: 'NONSENSE' })`, "unknown endpoint behavior"},
		{"transposition", `({ sid: 'fc00::1', behavior: 'END_DT4', structure: { transpositionLength: 16 } })`, "transpositionLength"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v, err := rt.RunString(tc.src)
			if err != nil {
				t.Fatalf("eval: %v", err)
			}
			_, err = parseSRv6L3Service(rt, v)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not contain %q", err.Error(), tc.want)
			}
		})
	}
}

func buildPrefixArrayJS(n int) string {
	var sb strings.Builder
	sb.Grow(n * 18)
	sb.WriteByte('[')
	for i := range n {
		if i > 0 {
			sb.WriteByte(',')
		}
		fmt.Fprintf(&sb, `"10.%d.%d.%d/32"`, (i>>16)&0xff, (i>>8)&0xff, i&0xff)
	}
	sb.WriteByte(']')
	return sb.String()
}

func BenchmarkParseRoutesArray_String10k(b *testing.B) {
	rt := newRT(b)
	arr := evalArray(b, rt, buildPrefixArrayJS(10000))
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, err := parseRoutesArray(rt, gobgp.RF_IPv4_UC, arr); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkParsePrefixList_10k(b *testing.B) {
	rt := newRT(b)
	obj := rt.NewObject()
	v, err := rt.RunString(buildPrefixArrayJS(10000))
	if err != nil {
		b.Fatal(err)
	}
	if err := obj.Set("prefixes", v); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, err := parsePrefixList(rt, obj); err != nil {
			b.Fatal(err)
		}
	}
}
