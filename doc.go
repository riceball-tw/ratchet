// Package ratchet enforces one-way, step-by-step crypto agility.
//
// Like a ratchet gear, a service's encryption scheme only moves forward. A
// scheme has one of two roles:
//
//   - Current: the single [Cipher] that encrypts all new data.
//   - DecryptOnly: [Decrypter] values used only to read, usually old data.
//
// Every ciphertext is wrapped in an [Envelope] that records the scheme version
// and key ID used to produce it, so readers always know which Decrypter to
// use. DecryptOnly schemes are accepted as Decrypters, so writing with an old
// scheme is impossible by construction. Config.OnNewerData reports data
// written with a higher version than Current, which signals a server running
// an older config than its peers, or a rollback.
//
// The package implements no algorithm; plug in any Cipher or Decrypter.
package ratchet
