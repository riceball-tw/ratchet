// Package ratchet is the algorithm-agnostic core of step-by-step crypto
// agility.
//
// Like a ratchet gear, the scheme a service uses to create values only moves
// forward. A scheme has one of two roles:
//
//   - Current: the single scheme that creates all new values.
//   - CheckOnly: schemes used only to check existing values (decrypt, verify),
//     usually old ones.
//
// Every stored value is wrapped in an [Envelope] that records the scheme
// version and key ID that produced it, so readers always know which scheme to
// use. A [Registry] maps each [Ref] to its scheme, and Config.OnNewerData
// reports values created with a higher version than Current, which signals a
// server running an older config than its peers, or a rollback.
//
// This package contains no algorithm-type logic. Packages such as
// ratchet/aead add the verbs for one algorithm type on top of [Registry].
package ratchet
