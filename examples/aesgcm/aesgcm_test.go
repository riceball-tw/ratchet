package aesgcm_test

import (
	"crypto/rand"
	"fmt"
	"testing"

	"example.com/ratchet"
	"example.com/ratchet/examples/aesgcm"
)

func TestTamperedRefFails(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	a, _ := aesgcm.New(ratchet.Ref{Version: 1, KeyID: "k"}, key)
	b, _ := aesgcm.New(ratchet.Ref{Version: 2, KeyID: "k"}, key) // same key, different version

	ct, _ := b.Encrypt([]byte("x"), nil)
	if _, err := a.Decrypt(ct, nil); err == nil {
		t.Fatal("relabelled ciphertext decrypted")
	}
}

func TestAADMismatchFails(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	c, _ := aesgcm.New(ratchet.Ref{Version: 1, KeyID: "k"}, key)
	ct, _ := c.Encrypt([]byte("x"), []byte("row:1"))
	if _, err := c.Decrypt(ct, []byte("row:2")); err == nil {
		t.Fatal("decrypted with wrong AAD")
	}
}

func Example() {
	key1 := make([]byte, 32)
	rand.Read(key1)
	v1, _ := aesgcm.New(ratchet.Ref{Version: 1, KeyID: "customer-2019"}, key1)

	r, _ := ratchet.New(ratchet.Config{Current: v1})
	aad := []byte("tenant/acme:customers:42:tax-id")
	stored, _ := r.Encrypt([]byte("A123456789"), aad)

	// Later deploy: v2 becomes current, v1 is read-only.
	key2 := make([]byte, 32)
	rand.Read(key2)
	v2, _ := aesgcm.New(ratchet.Ref{Version: 2, KeyID: "customer-2026-01"}, key2)
	r, _ = ratchet.New(ratchet.Config{
		Current:     v2,
		DecryptOnly: []ratchet.Decrypter{ratchet.ReadOnly(v1)},
	})

	pt, _ := r.Decrypt(stored, aad)
	fmt.Println(string(pt), r.NeedsRewrap(stored))

	stored, _, _ = r.Rewrap(stored, aad)
	fmt.Println(stored.Ref, r.NeedsRewrap(stored))

	// Output:
	// A123456789 true
	// v2/customer-2026-01 false
}
