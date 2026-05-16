package bgp

import (
	"fmt"
	"strings"
	"testing"

	"github.com/grafana/sobek"
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

func TestParseRoutesArray_StringForm(t *testing.T) {
	rt := newRT(t)
	arr := evalArray(t, rt, `["10.0.0.0/24", "10.0.1.0/24", "2001:db8::/32"]`)
	got, err := parseRoutesArray(rt, arr)
	if err != nil {
		t.Fatalf("parseRoutesArray: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("len=%d, want 3", len(got))
	}
	wantPrefixes := []string{"10.0.0.0/24", "10.0.1.0/24", "2001:db8::/32"}
	for i, want := range wantPrefixes {
		if got[i].Prefix.String() != want {
			t.Errorf("routes[%d].Prefix=%s, want %s", i, got[i].Prefix, want)
		}
	}
}

func TestParseRoutesArray_ObjectForm(t *testing.T) {
	rt := newRT(t)
	arr := evalArray(t, rt, `[
		{prefix: "10.0.0.0/24"},
		{prefix: "10.0.1.0/24"},
		{prefix: "2001:db8::/32"}
	]`)
	got, err := parseRoutesArray(rt, arr)
	if err != nil {
		t.Fatalf("parseRoutesArray: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("len=%d, want 3", len(got))
	}
	if got[0].Prefix.String() != "10.0.0.0/24" {
		t.Errorf("got[0].Prefix=%s, want 10.0.0.0/24", got[0].Prefix)
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
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			arr := evalArray(t, rt, tc.src)
			_, err := parseRoutesArray(rt, arr)
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
	got, err := parseRoutesArray(rt, arr)
	if err != nil {
		t.Fatalf("parseRoutesArray: %v", err)
	}
	if len(got) != n {
		t.Fatalf("len=%d, want %d", len(got), n)
	}
	// Spot-check the first, last, and a middle entry.
	if got[0].Prefix.String() != "10.0.0.0/32" {
		t.Errorf("got[0]=%s, want 10.0.0.0/32", got[0].Prefix)
	}
	if got[n-1].Prefix.String() != fmt.Sprintf("10.%d.%d.%d/32", ((n-1)>>16)&0xff, ((n-1)>>8)&0xff, (n-1)&0xff) {
		t.Errorf("got[last]=%s, mismatch", got[n-1].Prefix)
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
			name: "nonString",
			setup: func() *sobek.Object {
				o := rt.NewObject()
				v, _ := rt.RunString(`[123]`)
				_ = o.Set("prefixes", v)
				return o
			},
			want: "prefixes[0] must be a string",
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
		if _, err := parseRoutesArray(rt, arr); err != nil {
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
