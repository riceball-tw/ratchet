package ratchet

import (
	"errors"
	"fmt"
	"sync/atomic"
)

var (
	// ErrUnknownRef: no Decrypter is registered for an envelope's Ref.
	ErrUnknownRef = errors.New("ratchet: unknown scheme")
	// ErrInvalidConfig: the Config is inconsistent.
	ErrInvalidConfig = errors.New("ratchet: invalid config")
)

// Config describes the schemes this process uses.
type Config struct {
	// Current encrypts all new data. Required.
	Current Cipher
	// DecryptOnly schemes are only used for reading. Usually these are old
	// schemes; remove one once no data uses it (see Ratchet.Stats and
	// Ratchet.Rewrap). A DecryptOnly scheme may also have a higher version than
	// Current: deploy the next scheme this way to every server first, so all
	// servers can read it before any server writes it.
	DecryptOnly []Decrypter
	// OnNewerData, if set, is called when Decrypt sees an envelope whose
	// version is higher than Current's, whether or not it can be decrypted.
	// Briefly during a rolling deploy this is expected. If it persists, the
	// data was written by a newer scheme than this server writes: some server
	// runs a newer config, or this one was rolled back. It is called on the
	// Decrypt path, possibly concurrently, so keep it cheap (log or count).
	OnNewerData func(found, current Ref)
}

// Role of a scheme in a running Ratchet.
type Role int

const (
	RoleCurrent Role = iota
	RoleDecryptOnly
)

func (r Role) String() string {
	switch r {
	case RoleCurrent:
		return "current"
	case RoleDecryptOnly:
		return "decrypt-only"
	}
	return "unknown"
}

// Usage reports how often a scheme was used to decrypt since start-up.
// A DecryptOnly scheme whose Decrypts stays at zero through a full rewrap of
// the data is safe to remove from Config.DecryptOnly.
type Usage struct {
	Ref      Ref
	Role     Role
	Decrypts uint64
}

type entry struct {
	d        Decrypter
	role     Role
	decrypts atomic.Uint64
}

// Ratchet encrypts with the Current scheme and decrypts with any registered
// one. It is safe for concurrent use.
type Ratchet struct {
	current Cipher
	entries map[Ref]*entry
	order   []Ref
	onNewer func(found, current Ref)
}

// New validates cfg and returns a ready Ratchet.
func New(cfg Config) (*Ratchet, error) {
	if cfg.Current == nil {
		return nil, fmt.Errorf("%w: Current is required", ErrInvalidConfig)
	}
	cur := cfg.Current.Ref()
	if cur == Unversioned {
		return nil, fmt.Errorf("%w: Current cannot be Unversioned", ErrInvalidConfig)
	}

	r := &Ratchet{current: cfg.Current, entries: map[Ref]*entry{}, onNewer: cfg.OnNewerData}
	add := func(d Decrypter, role Role) error {
		ref := d.Ref()
		if err := ref.Validate(); err != nil {
			return err
		}
		if _, dup := r.entries[ref]; dup {
			return fmt.Errorf("%w: %s configured twice", ErrInvalidConfig, ref)
		}
		r.entries[ref] = &entry{d: d, role: role}
		r.order = append(r.order, ref)
		return nil
	}
	if err := add(cfg.Current, RoleCurrent); err != nil {
		return nil, err
	}
	for _, d := range cfg.DecryptOnly {
		if err := add(d, RoleDecryptOnly); err != nil {
			return nil, err
		}
	}
	return r, nil
}

// Current returns the Ref used for new data.
func (r *Ratchet) Current() Ref { return r.current.Ref() }

// Encrypt always uses the Current scheme.
func (r *Ratchet) Encrypt(plaintext, aad []byte) (Envelope, error) {
	ct, err := r.current.Encrypt(plaintext, aad)
	if err != nil {
		return Envelope{}, err
	}
	return Envelope{Ref: r.current.Ref(), Ciphertext: ct}, nil
}

// Decrypt picks the scheme recorded in env.
func (r *Ratchet) Decrypt(env Envelope, aad []byte) ([]byte, error) {
	if cur := r.current.Ref(); r.onNewer != nil && env.Version > cur.Version {
		r.onNewer(env.Ref, cur)
	}
	e, ok := r.entries[env.Ref]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrUnknownRef, env.Ref)
	}
	e.decrypts.Add(1)
	return e.d.Decrypt(env.Ciphertext, aad)
}

// NeedsRewrap reports whether env was written by a scheme other than Current.
func (r *Ratchet) NeedsRewrap(env Envelope) bool { return env.Ref != r.current.Ref() }

// Rewrap re-encrypts env under the Current scheme. It returns env unchanged
// and false if it is already current. Use it in backfill jobs, or lazily when
// reading a record, to drain old DecryptOnly schemes before removing them.
func (r *Ratchet) Rewrap(env Envelope, aad []byte) (Envelope, bool, error) {
	if !r.NeedsRewrap(env) {
		return env, false, nil
	}
	pt, err := r.Decrypt(env, aad)
	if err != nil {
		return Envelope{}, false, err
	}
	out, err := r.Encrypt(pt, aad)
	clear(pt)
	if err != nil {
		return Envelope{}, false, err
	}
	return out, true, nil
}

// Stats reports per-scheme decrypt counts since start-up.
func (r *Ratchet) Stats() []Usage {
	out := make([]Usage, 0, len(r.order))
	for _, ref := range r.order {
		e := r.entries[ref]
		out = append(out, Usage{Ref: ref, Role: e.role, Decrypts: e.decrypts.Load()})
	}
	return out
}
