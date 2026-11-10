package ratchet

import (
	"errors"
	"fmt"
)

var (
	// ErrUnknownRef: no scheme is registered for a Ref.
	ErrUnknownRef = errors.New("ratchet: unknown scheme")
	// ErrInvalidConfig: the Config is inconsistent.
	ErrInvalidConfig = errors.New("ratchet: invalid config")
)

// Scheme is anything identified by a Ref.
type Scheme interface {
	Ref() Ref
}

// Config describes the schemes a Registry holds. R is the "check" side of an
// algorithm type: a decrypter, a verifier, and so on.
type Config[R Scheme] struct {
	// Current is the check side of the scheme that creates all new values.
	// Required.
	Current R
	// CheckOnly schemes are only used to check existing values. Usually these
	// are old schemes; remove one once no stored value uses it. A CheckOnly
	// scheme may also have a higher version than Current: deploy the next
	// scheme this way to every server first, so all servers can check its
	// values before any server creates them.
	CheckOnly []R
	// OnNewerData, if set, is called when Lookup sees a Ref whose version is
	// higher than Current's, whether or not it is registered. Briefly during
	// a rolling deploy this is expected. If it persists, the value was created
	// by a newer scheme than this server creates: some server runs a newer
	// config, or this one was rolled back. It is called on the Lookup path,
	// possibly concurrently, so keep it cheap (log or count).
	OnNewerData func(found, current Ref)
}

// Registry finds the scheme for a Ref. It holds no algorithm-specific logic;
// algorithm-type packages such as ratchet/aead build on it. It is safe for
// concurrent use.
type Registry[R Scheme] struct {
	current Ref
	schemes map[Ref]R
	onNewer func(found, current Ref)
}

// New validates cfg and returns a ready Registry.
func New[R Scheme](cfg Config[R]) (*Registry[R], error) {
	if any(cfg.Current) == nil {
		return nil, fmt.Errorf("%w: Current is required", ErrInvalidConfig)
	}
	cur := cfg.Current.Ref()
	if cur == Unversioned {
		return nil, fmt.Errorf("%w: Current cannot be Unversioned", ErrInvalidConfig)
	}

	r := &Registry[R]{current: cur, schemes: map[Ref]R{}, onNewer: cfg.OnNewerData}
	for _, s := range append([]R{cfg.Current}, cfg.CheckOnly...) {
		ref := s.Ref()
		if err := ref.Validate(); err != nil {
			return nil, err
		}
		if _, dup := r.schemes[ref]; dup {
			return nil, fmt.Errorf("%w: %s configured twice", ErrInvalidConfig, ref)
		}
		r.schemes[ref] = s
	}
	return r, nil
}

// Current returns the Ref of the scheme that creates new values.
func (r *Registry[R]) Current() Ref { return r.current }

// Lookup returns the scheme registered for ref.
func (r *Registry[R]) Lookup(ref Ref) (R, error) {
	if r.onNewer != nil && ref.Version > r.current.Version {
		r.onNewer(ref, r.current)
	}
	s, ok := r.schemes[ref]
	if !ok {
		var zero R
		return zero, fmt.Errorf("%w: %s", ErrUnknownRef, ref)
	}
	return s, nil
}
