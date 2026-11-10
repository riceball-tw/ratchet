package ratchet

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Ref identifies a scheme: the version decides the algorithm and its
// parameters, the key ID decides which key material is used. Key IDs are not
// secret.
type Ref struct {
	Version uint32 `json:"v"`
	KeyID   string `json:"kid"`
}

// Unversioned is the Ref given to data written before the ratchet was adopted
// (anything that does not start with the envelope prefix). Register a scheme
// for it in Config.CheckOnly to keep reading such data.
var Unversioned = Ref{}

func (r Ref) String() string {
	if r == Unversioned {
		return "unversioned"
	}
	return fmt.Sprintf("v%d/%s", r.Version, r.KeyID)
}

// Validate reports whether r is Unversioned or a well-formed versioned Ref:
// version > 0 and a key ID of printable ASCII without ':' or spaces.
func (r Ref) Validate() error {
	if r == Unversioned {
		return nil
	}
	if r.Version == 0 {
		return fmt.Errorf("ratchet: %s: version 0 is reserved for Unversioned", r)
	}
	if r.KeyID == "" {
		return fmt.Errorf("ratchet: %s: empty key id", r)
	}
	for _, c := range r.KeyID {
		if c == ':' || c < 0x21 || c > 0x7e {
			return fmt.Errorf("ratchet: %s: key id must be printable ASCII without ':' or spaces", r)
		}
	}
	return nil
}

// Envelope is a ciphertext together with the Ref that produced it.
type Envelope struct {
	Ref
	Ciphertext []byte
}

const envelopePrefix = "rk1:"

var ErrMalformed = errors.New("ratchet: malformed envelope")

// MarshalText encodes the envelope as rk1:<version>:<kid>:<base64url ciphertext>.
// An Unversioned envelope is returned as its raw ciphertext.
func (e Envelope) MarshalText() ([]byte, error) {
	if e.Ref == Unversioned {
		return bytes.Clone(e.Ciphertext), nil
	}
	if err := e.Ref.Validate(); err != nil {
		return nil, err
	}
	s := envelopePrefix + strconv.FormatUint(uint64(e.Version), 10) + ":" + e.KeyID + ":" +
		base64.RawURLEncoding.EncodeToString(e.Ciphertext)
	return []byte(s), nil
}

// UnmarshalText parses the format written by MarshalText. Input without the
// envelope prefix is treated as Unversioned legacy data.
func (e *Envelope) UnmarshalText(b []byte) error {
	s := string(b)
	if !strings.HasPrefix(s, envelopePrefix) {
		*e = Envelope{Ref: Unversioned, Ciphertext: bytes.Clone(b)}
		return nil
	}
	parts := strings.SplitN(s[len(envelopePrefix):], ":", 3)
	if len(parts) != 3 {
		return ErrMalformed
	}
	v, err := strconv.ParseUint(parts[0], 10, 32)
	if err != nil {
		return ErrMalformed
	}
	ref := Ref{Version: uint32(v), KeyID: parts[1]}
	if ref == Unversioned || ref.Validate() != nil {
		return ErrMalformed
	}
	ct, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return ErrMalformed
	}
	*e = Envelope{Ref: ref, Ciphertext: ct}
	return nil
}

func (e Envelope) String() string {
	b, err := e.MarshalText()
	if err != nil {
		return ""
	}
	return string(b)
}

// ParseEnvelope is a convenience wrapper around UnmarshalText.
func ParseEnvelope(s string) (Envelope, error) {
	var e Envelope
	err := e.UnmarshalText([]byte(s))
	return e, err
}
