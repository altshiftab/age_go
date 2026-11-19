# age_go

The [age v1 format](https://c2sp.org/age) in Go, as a streaming writer and reader, to a passphrase or to X25519 recipients. It covers the specification's two core recipient types, scrypt and X25519, and the binary encoding. It leaves out the hybrid post-quantum recipients, plugins and the ASCII armor. Within that scope the format is the specification's, so the `age` command decrypts what this writes and this decrypts what `age` writes: files encrypted with it do not depend on this code surviving.

## pkg/age

- **Passphrase:** `NewScryptWriter` and `NewScryptReader`. A passphrase-encrypted file has one stanza, and a header that offers anything beside it is refused.
- **X25519:** `NewX25519Writer` encrypts to any number of recipients, and `NewX25519Reader` decrypts with whichever of the identities it is given matches. Keys are written as age writes them:
  - `ParseX25519Recipient` reads `age1…`.
  - `ParseX25519Identity` reads `AGE-SECRET-KEY-1…`.
  - `GenerateX25519Identity` makes one, as `age-keygen` does.
  - `String` writes either back.
- **One-way encryption:** a program holding only the recipient can encrypt but never decrypt.
- **Errors:** decryption failures fall into the specification's classes, `ErrHeader`, `ErrNoMatch`, `ErrHmac` and `ErrPayload`. Key-parsing failures are `ErrParseError`s.
- **Releasing plaintext:** the readers release it a chunk at a time, each only after the chunk has authenticated.
- **Dependency:** `golang.org/x/crypto`, for ChaCha20-Poly1305 and scrypt. The standard library vendors the same AEAD but does not export it, and an AEAD is the one place where writing it by hand would cost more than the dependency. Everything else is written on the standard library: X25519 (`crypto/ecdh`), the header, its HMAC, HKDF and the STREAM construction.
- **Tests:**
  - The specification's own vectors, in `testdata/cctv`, copied from [C2SP/CCTV](https://github.com/C2SP/CCTV/tree/main/age/testdata) under 0BSD. 93 of the 147 apply: the rest are armored or open only with a hybrid identity.
  - Round trips at the chunk boundaries, to one and to several recipients.
  - A tamper table on a three-chunk file.
  - Cross-tests against the `age` and `age-keygen` commands in both directions, skipped where they are not installed.

## pkg/bech32

Bech32 (BIP 173), the encoding of age's keys: `Encode` and `Decode`. It is the original Bech32 rather than Bech32m, and like age's own it sets no limit on length.
- Mixed case, characters outside the charset, a wrong checksum and non-zero padding are all parse errors.
- Tested with BIP 173's vectors.
