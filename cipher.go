package ratchet

// Decrypter can only read data. Config.DecryptOnly schemes are Decrypters.
type Decrypter interface {
	Ref() Ref
	Decrypt(ciphertext, aad []byte) ([]byte, error)
}

// Encrypter can write data.
type Encrypter interface {
	Ref() Ref
	Encrypt(plaintext, aad []byte) ([]byte, error)
}

// Cipher is required only for the Current scheme.
//
// The ratchet does not implement any algorithm; bring your own. A Cipher
// should authenticate its Ref together with aad (for example by prefixing it
// to the AEAD's additional data), so that relabeling an Envelope's version
// or key ID makes decryption fail.
type Cipher interface {
	Encrypter
	Decrypter
}

// ReadOnly hides the Encrypt method of c, so it can be handed to code that
// must never write with it.
func ReadOnly(c Decrypter) Decrypter { return readOnly{c} }

type readOnly struct{ d Decrypter }

func (r readOnly) Ref() Ref                               { return r.d.Ref() }
func (r readOnly) Decrypt(ct, aad []byte) ([]byte, error) { return r.d.Decrypt(ct, aad) }

// DecrypterFunc adapts an existing decryption routine, typically the one used
// for data written before the ratchet was adopted, into a Decrypter.
func DecrypterFunc(ref Ref, fn func(ciphertext, aad []byte) ([]byte, error)) Decrypter {
	return funcDecrypter{ref, fn}
}

type funcDecrypter struct {
	ref Ref
	fn  func(ciphertext, aad []byte) ([]byte, error)
}

func (f funcDecrypter) Ref() Ref                               { return f.ref }
func (f funcDecrypter) Decrypt(ct, aad []byte) ([]byte, error) { return f.fn(ct, aad) }
