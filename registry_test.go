package ratchet

import (
	"errors"
	"fmt"
	"testing"
)

type fakeScheme struct{ ref Ref }

func (f fakeScheme) Ref() Ref { return f.ref }

func scheme(v uint32, kid string) Scheme { return fakeScheme{Ref{Version: v, KeyID: kid}} }

func TestLookup(t *testing.T) {
	v1, v2 := scheme(1, "a"), scheme(2, "b")
	r, err := New(Config[Scheme]{Current: v2, CheckOnly: []Scheme{v1}})
	if err != nil {
		t.Fatal(err)
	}
	if r.Current() != v2.Ref() {
		t.Fatalf("current %s", r.Current())
	}
	for _, s := range []Scheme{v1, v2} {
		got, err := r.Lookup(s.Ref())
		if err != nil || got != s {
			t.Fatalf("lookup %s: %v %v", s.Ref(), got, err)
		}
	}
	if _, err := r.Lookup(Ref{Version: 1, KeyID: "gone"}); !errors.Is(err, ErrUnknownRef) {
		t.Fatalf("unknown: %v", err)
	}
}

func TestOnNewerData(t *testing.T) {
	v1, v2 := scheme(1, "a"), scheme(2, "b")
	var seen []string
	r, err := New(Config[Scheme]{
		Current:   v1,
		CheckOnly: []Scheme{v2}, // prepared: checkable before it becomes Current
		OnNewerData: func(found, current Ref) {
			seen = append(seen, found.String()+">"+current.String())
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	r.Lookup(v1.Ref())
	if _, err := r.Lookup(v2.Ref()); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Lookup(Ref{Version: 3, KeyID: "c"}); !errors.Is(err, ErrUnknownRef) {
		t.Fatalf("unknown newer: %v", err)
	}
	want := []string{"v2/b>v1/a", "v3/c>v1/a"}
	if fmt.Sprint(seen) != fmt.Sprint(want) {
		t.Fatalf("got %v, want %v", seen, want)
	}
}

func TestKeyRotationSameVersion(t *testing.T) {
	a, b := scheme(2, "2026-01"), scheme(2, "2026-07")
	r, err := New(Config[Scheme]{Current: b, CheckOnly: []Scheme{a}})
	if err != nil || r.Current() != b.Ref() {
		t.Fatalf("rotation: %v", err)
	}
}

func TestInvalidConfig(t *testing.T) {
	for name, cfg := range map[string]Config[Scheme]{
		"no current":          {},
		"unversioned current": {Current: scheme(0, "")},
		"duplicate":           {Current: scheme(1, "a"), CheckOnly: []Scheme{scheme(1, "a")}},
	} {
		if _, err := New(cfg); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestEnvelopeFormat(t *testing.T) {
	env := Envelope{Ref: Ref{Version: 2, KeyID: "customer-2026-01"}, Ciphertext: []byte{0xff, 0x00}}
	if got, want := env.String(), "rk1:2:customer-2026-01:_wA"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	for _, bad := range []string{"rk1:", "rk1:2:k", "rk1:0:k:AA", "rk1:x:k:AA", "rk1:2::AA", "rk1:2:k:!!"} {
		if _, err := ParseEnvelope(bad); !errors.Is(err, ErrMalformed) {
			t.Errorf("%q: %v", bad, err)
		}
	}
}
