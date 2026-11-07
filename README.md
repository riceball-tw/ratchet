# ratchet

A minimal Go library for step-by-step crypto agility, based on the encrypt/decrypt interface from
[密碼學敏捷性：把「密碼有天會被攻破」作為系統設計前提](https://www.webdong.dev/zh-tw/post/crypto-agility/).

Like a ratchet gear, the encryption scheme only moves forward. There are two roles:

| Role        | Type        | Encrypt | Decrypt | Meaning                               |
| ----------- | ----------- | ------- | ------- | ------------------------------------- |
| **Current** | `Cipher`    | yes     | yes     | The one scheme all new data uses      |
| **DecryptOnly** | `Decrypter` | no  | yes     | Old schemes, or the next one being rolled out |

DecryptOnly schemes are `Decrypter`s, so writing with an old scheme does not compile.

| Article principle            | Library feature                                              |
| ---------------------------- | ------------------------------------------------------------ |
| Identify (version + `kid`)   | `Envelope` → `rk1:<version>:<kid>:<base64url>`               |
| Select (central policy)      | `Config.Current` is the only `Cipher` that encrypts           |
| Coexist (old is read-only)   | `Config.DecryptOnly []Decrypter`; `ReadOnly()` strips `Encrypt`    |
| Rotate and retire            | Move Current to DecryptOnly, `Rewrap`, then remove it     |
| Observable                   | `Stats()` decrypt counts per scheme, `NeedsRewrap`            |

`Version` identifies the algorithm and its parameters. `KeyID` identifies the key. Rotating to a new key under the same version is allowed.

## Step by step

### Step 0: Adopt

Wrap your existing decrypt routine. Data with no `rk1:` prefix is treated as `ratchet.Unversioned`.

```go
unversioned := ratchet.DecrypterFunc(ratchet.Unversioned, oldDecrypt)
v1 := myCipher(ratchet.Ref{Version: 1, KeyID: "customer-2019"}) // any ratchet.Cipher

r, err := ratchet.New(ratchet.Config{
    Current:     v1,
    DecryptOnly: []ratchet.Decrypter{unversioned},
})
```

### Step 1: Route all writes through the ratchet

```go
env, _ := r.Encrypt(plaintext, aad)       // always Current
db.Save(id, env.String())                 // "rk1:1:customer-2019:..."

env, _ := ratchet.ParseEnvelope(stored)
pt, _ := r.Decrypt(env, aad)              // picks the scheme by (version, kid)
```

Use a stable record identity (tenant/table/row/field) as AAD, so a ciphertext cannot be copied to another row.

### Step 2: Upgrade in two deploys

Servers usually restart one at a time, so for a while some run the new config and some the old one. If a new server writes v2 while an old one only knows v1, the old one fails to read that data. Avoid it with two deploys:

```go
// Deploy 2a, to every server: still write v1, but v2 is now readable.
ratchet.Config{Current: v1, DecryptOnly: []ratchet.Decrypter{unversioned, v2}}

// Deploy 2b, after 2a reached every server: write v2, v1 becomes read-only.
ratchet.Config{Current: v2, DecryptOnly: []ratchet.Decrypter{unversioned, ratchet.ReadOnly(v1)}}
```

If all servers switch at once (single instance, or a blue-green switch), deploy 2b directly.

#### Detect version mismatches with `OnNewerData`

```go
ratchet.Config{
    Current:     v2,
    DecryptOnly: []ratchet.Decrypter{unversioned, ratchet.ReadOnly(v1)},
    OnNewerData: func(found, current ratchet.Ref) {
        log.Printf("ratchet: read %s data but this server writes %s", found, current)
        newerDataCounter.Inc()
    },
}
```

It fires when `Decrypt` sees data with a higher version than Current:

- During deploy 2b, briefly: expected (servers still on 2a read v2 data).
- Lasting after the deploy: a server runs an old config, or was rolled back. Alert on this.
- With `ErrUnknownRef`: the server cannot read that data at all. Deploy 2a was skipped, or a full rollback happened.

### Step 3: Migrate

```go
if r.NeedsRewrap(env) {
    env, _, err = r.Rewrap(env, aad)      // decrypt with old scheme, encrypt with Current
    db.Save(id, env.String())
}
```

Run this as a backfill job, or lazily on read. Watch `r.Stats()`.

### Step 4: Remove old schemes

> **Check first.** After a scheme is removed from `DecryptOnly`, data still encrypted with it can no longer be decrypted (`ErrUnknownRef`). Remove it only after the backfill finished and `Stats()` shows zero decrypts for it.

```go
ratchet.Config{Current: v2}
```

Repeat from Step 2 when the next algorithm arrives (for example, a PQC hybrid).

## Bring your own algorithm

The `ratchet` package implements no algorithm. Implement `Decrypter` for a read-only scheme, or `Cipher` (Ref + Encrypt + Decrypt) for a scheme that can become Current. Any algorithm works: AES-GCM, ChaCha20-Poly1305, a KMS call, a PQC hybrid.

Bind `Ref` into the authenticated data, so that relabeling an envelope's version or key ID makes decryption fail.

`examples/aesgcm` is reference code to copy: an AES-GCM `Cipher` with `Ref` bound into the AAD, plus a full `Example`. It is not part of the core API.
