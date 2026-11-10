// Package aead applies the ratchet to encryption: one Current Cipher encrypts
// all new data, and DecryptOnly schemes only read existing data.
//
// The package implements no algorithm; plug in any Cipher or Decrypter.
package aead

import "example.com/ratchet"

// Decrypter can only read data. Config.DecryptOnly schemes are Decrypters.
type Decrypter interface {
	Ref() ratchet.Ref
	Decrypt(ciphertext, aad []byte) ([]byte, error)
}

// Cipher is required only for the Current scheme.
//
// A Cipher should authenticate its Ref together with aad (for example by
// prefixing it to the AEAD's additional data), so that relabeling an
// Envelope's version or key ID makes decryption fail.
type Cipher interface {
	Decrypter
	Encrypt(plaintext, aad []byte) ([]byte, error)
}

// DecrypterFunc adapts an existing decryption routine, typically the one used
// for data written before the ratchet was adopted, into a Decrypter.
func DecrypterFunc(ref ratchet.Ref, fn func(ciphertext, aad []byte) ([]byte, error)) Decrypter {
	return funcDecrypter{ref, fn}
}

type funcDecrypter struct {
	ref ratchet.Ref
	fn  func(ciphertext, aad []byte) ([]byte, error)
}

func (f funcDecrypter) Ref() ratchet.Ref                       { return f.ref }
func (f funcDecrypter) Decrypt(ct, aad []byte) ([]byte, error) { return f.fn(ct, aad) }

// Config describes the encryption schemes this process uses.
type Config struct {
	// Current encrypts all new data. Required.
	Current Cipher
	// DecryptOnly schemes are only used for reading: old schemes, or the next
	// scheme being rolled out. See ratchet.Config.CheckOnly.
	DecryptOnly []Decrypter
	// OnNewerData: see ratchet.Config.OnNewerData.
	OnNewerData func(found, current ratchet.Ref)
}

// Ratchet encrypts with the Current scheme and decrypts with any registered
// one. It is safe for concurrent use.
type Ratchet struct {
	current Cipher
	reg     *ratchet.Registry[Decrypter]
}

// New validates cfg and returns a ready Ratchet.
func New(cfg Config) (*Ratchet, error) {
	reg, err := ratchet.New(ratchet.Config[Decrypter]{
		Current:     cfg.Current,
		CheckOnly:   cfg.DecryptOnly,
		OnNewerData: cfg.OnNewerData,
	})
	if err != nil {
		return nil, err
	}
	return &Ratchet{current: cfg.Current, reg: reg}, nil
}

// Current returns the Ref used for new data.
func (r *Ratchet) Current() ratchet.Ref { return r.reg.Current() }

// Encrypt always uses the Current scheme.
func (r *Ratchet) Encrypt(plaintext, aad []byte) (ratchet.Envelope, error) {
	ct, err := r.current.Encrypt(plaintext, aad)
	if err != nil {
		return ratchet.Envelope{}, err
	}
	return ratchet.Envelope{Ref: r.current.Ref(), Ciphertext: ct}, nil
}

// Decrypt picks the scheme recorded in env.
func (r *Ratchet) Decrypt(env ratchet.Envelope, aad []byte) ([]byte, error) {
	d, err := r.reg.Lookup(env.Ref)
	if err != nil {
		return nil, err
	}
	return d.Decrypt(env.Ciphertext, aad)
}

// Rewrap re-encrypts env under the Current scheme. It returns env unchanged
// and false if it is already current. Use it in backfill jobs, or lazily when
// reading a record, to drain old DecryptOnly schemes before removing them.
func (r *Ratchet) Rewrap(env ratchet.Envelope, aad []byte) (ratchet.Envelope, bool, error) {
	if env.Ref == r.Current() {
		return env, false, nil
	}
	pt, err := r.Decrypt(env, aad)
	if err != nil {
		return ratchet.Envelope{}, false, err
	}
	out, err := r.Encrypt(pt, aad)
	clear(pt)
	if err != nil {
		return ratchet.Envelope{}, false, err
	}
	return out, true, nil
}
