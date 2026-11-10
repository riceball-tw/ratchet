// Package aesgcm is a reference aead.Cipher built on AES-GCM. It shows how
// to plug an algorithm into the ratchet; copy and adapt it, or write your own
// Cipher for any other algorithm.
package aesgcm

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"

	"example.com/ratchet"
	"example.com/ratchet/aead"
)

// New returns an AES-GCM Cipher. key must be 16, 24 or 32 bytes; prefer 32
// (AES-256) for long-lived data.
//
// Nonces are random (96-bit), so a single key should not encrypt more than
// about 2^32 messages; rotate the key ID well before that.
//
// The Ref is bound into the authenticated data, so an envelope whose version
// or key ID was tampered with fails to decrypt.
func New(ref ratchet.Ref, key []byte) (aead.Cipher, error) {
	if ref == ratchet.Unversioned {
		return nil, fmt.Errorf("aesgcm: needs a versioned Ref")
	}
	if err := ref.Validate(); err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aesgcm: %s: %w", ref, err)
	}
	gcm, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return nil, fmt.Errorf("aesgcm: %s: %w", ref, err)
	}
	return &aesGCM{ref: ref, gcm: gcm}, nil
}

type aesGCM struct {
	ref ratchet.Ref
	gcm cipher.AEAD
}

func (c *aesGCM) Ref() ratchet.Ref { return c.ref }

func (c *aesGCM) Encrypt(plaintext, aad []byte) ([]byte, error) {
	return c.gcm.Seal(nil, nil, plaintext, bindAAD(c.ref, aad)), nil
}

func (c *aesGCM) Decrypt(ciphertext, aad []byte) ([]byte, error) {
	return c.gcm.Open(nil, nil, ciphertext, bindAAD(c.ref, aad))
}

// bindAAD prefixes the caller's AAD with an unambiguous encoding of ref.
func bindAAD(ref ratchet.Ref, aad []byte) []byte {
	b := make([]byte, 0, 8+len(ref.KeyID)+len(aad))
	b = binary.BigEndian.AppendUint32(b, ref.Version)
	b = binary.BigEndian.AppendUint32(b, uint32(len(ref.KeyID)))
	b = append(b, ref.KeyID...)
	return append(b, aad...)
}
