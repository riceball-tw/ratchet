package aead

import (
	"bytes"
	"errors"
	"fmt"
	"testing"

	"example.com/ratchet"
)

// fakeCipher is not encryption. It tags data with its Ref and AAD so tests can
// check that the ratchet routes each envelope to the right scheme.
type fakeCipher struct{ ref ratchet.Ref }

func fake(v uint32, kid string) Cipher { return fakeCipher{ratchet.Ref{Version: v, KeyID: kid}} }

func (f fakeCipher) Ref() ratchet.Ref { return f.ref }

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

func roundTrip(t *testing.T, r *Ratchet, env ratchet.Envelope, aad, want []byte) {
	t.Helper()
	parsed, err := ratchet.ParseEnvelope(env.String())
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
	unversioned := DecrypterFunc(ratchet.Unversioned, func(ct, _ []byte) ([]byte, error) {
		return bytes.TrimPrefix(ct, []byte("plain:")), nil
	})
	v1 := fake(1, "customer-2019")
	r := mustNew(t, Config{Current: v1, DecryptOnly: []Decrypter{unversioned}})
	old, _ := ratchet.ParseEnvelope("plain:A123456789")
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
	for _, env := range []ratchet.Envelope{old, e1, e2} {
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
	if _, err := r.Decrypt(e1, aad); !errors.Is(err, ratchet.ErrUnknownRef) {
		t.Fatalf("decrypt dropped: %v", err)
	}
}

func TestOnNewerDataPassedThrough(t *testing.T) {
	v1, v2 := fake(1, "a"), fake(2, "b")
	var calls int
	r := mustNew(t, Config{
		Current:     v1,
		DecryptOnly: []Decrypter{v2},
		OnNewerData: func(found, current ratchet.Ref) { calls++ },
	})
	ct, _ := v2.Encrypt([]byte("x"), nil)
	if _, err := r.Decrypt(ratchet.Envelope{Ref: v2.Ref(), Ciphertext: ct}, nil); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("hook called %d times", calls)
	}
}

func TestMissingCurrent(t *testing.T) {
	if _, err := New(Config{}); !errors.Is(err, ratchet.ErrInvalidConfig) {
		t.Fatalf("got %v", err)
	}
}
