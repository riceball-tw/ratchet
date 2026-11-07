package ratchet

import (
	"bytes"
	"errors"
	"fmt"
	"testing"
)

// fakeCipher is not encryption. It tags data with its Ref and AAD so tests can
// check that the ratchet routes each envelope to the right scheme.
type fakeCipher struct{ ref Ref }

func fake(v uint32, kid string) Cipher { return fakeCipher{Ref{Version: v, KeyID: kid}} }

func (f fakeCipher) Ref() Ref { return f.ref }

func (f fakeCipher) tag(aad []byte) []byte { return fmt.Appendf(nil, "%s|%s|", f.ref, aad) }

func (f fakeCipher) Encrypt(pt, aad []byte) ([]byte, error) {
	return append(f.tag(aad), pt...), nil
}

func (f fakeCipher) Decrypt(ct, aad []byte) ([]byte, error) {
	pt, ok := bytes.CutPrefix(ct, f.tag(aad))
	if !ok {
		return nil, errors.New("fake: wrong scheme or aad")
	}
	return pt, nil
}

func mustNew(t *testing.T, cfg Config) *Ratchet {
	t.Helper()
	r, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func roundTrip(t *testing.T, r *Ratchet, env Envelope, aad, want []byte) {
	t.Helper()
	parsed, err := ParseEnvelope(env.String())
	if err != nil {
		t.Fatal(err)
	}
	got, err := r.Decrypt(parsed, aad)
	if err != nil {
		t.Fatalf("decrypt %s: %v", env.Ref, err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestUpgradeFlow(t *testing.T) {
	aad := []byte("tenant/acme:customers:42:tax-id")
	pt := []byte("A123456789")

	// Step 0: data written before adoption, with no envelope.
	unversioned := DecrypterFunc(Unversioned, func(ct, _ []byte) ([]byte, error) {
		return bytes.TrimPrefix(ct, []byte("plain:")), nil
	})
	v1 := fake(1, "customer-2019")
	r := mustNew(t, Config{Current: v1, DecryptOnly: []Decrypter{unversioned}})
	old, _ := ParseEnvelope("plain:A123456789")
	roundTrip(t, r, old, aad, pt)
	e1, _ := r.Encrypt(pt, aad)
	if e1.Ref != v1.Ref() {
		t.Fatalf("encrypted with %s", e1.Ref)
	}

	// Step 1: upgrade. v2 writes, v1 becomes read-only.
	v2 := fake(2, "customer-2026-01")
	r = mustNew(t, Config{Current: v2, DecryptOnly: []Decrypter{unversioned, v1}})
	e2, _ := r.Encrypt(pt, aad)
	if e2.Ref != v2.Ref() {
		t.Fatalf("encrypted with %s", e2.Ref)
	}
	roundTrip(t, r, e1, aad, pt)
	roundTrip(t, r, e2, aad, pt)

	// Step 2: rewrap old data.
	for _, env := range []Envelope{old, e1, e2} {
		out, changed, err := r.Rewrap(env, aad)
		if err != nil {
			t.Fatal(err)
		}
		if changed != (env.Ref != v2.Ref()) || out.Ref != v2.Ref() {
			t.Fatalf("rewrap %s: changed=%v out=%s", env.Ref, changed, out.Ref)
		}
		roundTrip(t, r, out, aad, pt)
	}

	// Step 3: drop old schemes; old envelopes are no longer readable.
	r = mustNew(t, Config{Current: v2})
	if _, err := r.Decrypt(e1, aad); !errors.Is(err, ErrUnknownRef) {
		t.Fatalf("decrypt dropped: %v", err)
	}
}

func TestOnNewerData(t *testing.T) {
	v1, v2, v3 := fake(1, "a"), fake(2, "b"), fake(3, "c")
	var seen []string
	r := mustNew(t, Config{
		Current:     v1,
		DecryptOnly: []Decrypter{v2}, // prepared: readable before it becomes Current
		OnNewerData: func(found, current Ref) {
			seen = append(seen, found.String()+">"+current.String())
		},
	})
	seal := func(c Cipher) Envelope {
		ct, _ := c.Encrypt([]byte("x"), nil)
		return Envelope{Ref: c.Ref(), Ciphertext: ct}
	}

	if _, err := r.Decrypt(seal(v1), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Decrypt(seal(v2), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Decrypt(seal(v3), nil); !errors.Is(err, ErrUnknownRef) {
		t.Fatalf("unknown newer: %v", err)
	}
	want := []string{"v2/b>v1/a", "v3/c>v1/a"}
	if fmt.Sprint(seen) != fmt.Sprint(want) {
		t.Fatalf("got %v, want %v", seen, want)
	}
}

func TestKeyRotationSameVersion(t *testing.T) {
	a, b := fake(2, "2026-01"), fake(2, "2026-07")
	r := mustNew(t, Config{Current: b, DecryptOnly: []Decrypter{a}})
	if r.Current() != b.Ref() {
		t.Fatal("rotation failed")
	}
}

func TestInvalidConfig(t *testing.T) {
	for name, cfg := range map[string]Config{
		"no current":          {},
		"unversioned current": {Current: fake(0, "")},
		"duplicate":           {Current: fake(1, "a"), DecryptOnly: []Decrypter{fake(1, "a")}},
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
