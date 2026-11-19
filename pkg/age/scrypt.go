package age

import (
	"crypto/rand"
	"fmt"
	"strconv"

	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/scrypt"
)

const (
	scryptKind     = "scrypt"
	scryptLabel    = "age-encryption.org/v1/scrypt"
	scryptSaltSize = 16
	// wrappedKeySize is the file key sealed: the key and its tag.
	wrappedKeySize = fileKeySize + chacha20poly1305.Overhead
)

func scryptKey(passphrase []byte, salt []byte, workFactor int) ([]byte, error) {
	key, err := scrypt.Key(passphrase, append([]byte(scryptLabel), salt...), 1<<workFactor, 8, 1, chacha20poly1305.KeySize)
	if err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("scrypt key: %w", err))
	}

	return key, nil
}

// wrapScrypt seals the file key under a key derived from the passphrase, as
// the one stanza of a header.
func wrapScrypt(fileKey []byte, passphrase []byte, workFactor int) (*stanza, error) {
	salt := make([]byte, scryptSaltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("rand read (salt): %w", err))
	}

	key, err := scryptKey(passphrase, salt, workFactor)
	if err != nil {
		return nil, fmt.Errorf("scrypt key: %w", err)
	}

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("chacha20poly1305 new: %w", err))
	}

	// The key is used for this one seal, so a nonce of zeros is safe.
	body := aead.Seal(nil, make([]byte, chacha20poly1305.NonceSize), fileKey, noAdditionalData)

	return &stanza{
		kind: scryptKind,
		args: []string{b64.EncodeToString(salt), strconv.Itoa(workFactor)},
		body: body,
	}, nil
}

// parseWorkFactor reads a work factor written as the format requires: decimal,
// with no sign and no leading zero.
func parseWorkFactor(s string, maxWorkFactor int) (int, error) {
	if s == "" || s[0] == '0' {
		return 0, headerError(fmt.Sprintf("work factor %q is empty or starts with zero", s))
	}
	for i := range len(s) {
		if s[i] < '0' || s[i] > '9' {
			return 0, headerError(fmt.Sprintf("work factor %q is not decimal", s))
		}
	}

	workFactor, err := strconv.Atoi(s)
	if err != nil {
		return 0, headerErrorWith(fmt.Sprintf("work factor %q: strconv atoi", s), err)
	}
	if workFactor > maxWorkFactor {
		return 0, headerError(fmt.Sprintf("work factor %d is above the %d allowed", workFactor, maxWorkFactor))
	}

	return workFactor, nil
}

// unwrapScrypt finds the scrypt stanza and opens the file key it seals.
func unwrapScrypt(stanzas []*stanza, passphrase []byte, maxWorkFactor int) ([]byte, error) {
	var found *stanza
	for _, s := range stanzas {
		if s.kind != scryptKind {
			continue
		}
		// A passphrase is meant to be the file's only key. A header that
		// also offers some other way in, or a second passphrase, is refused
		// rather than half-trusted.
		if len(stanzas) != 1 {
			return nil, headerError("a scrypt stanza is not alone in the header")
		}
		found = s
	}
	if found == nil {
		return nil, altshiftErrors.NewWithTrace(ErrNoMatch)
	}

	if len(found.args) != 2 {
		return nil, headerError(fmt.Sprintf("a scrypt stanza has %d arguments, not 2", len(found.args)))
	}
	salt, err := decodeB64(found.args[0])
	if err != nil {
		return nil, fmt.Errorf("decode b64 (salt): %w", err)
	}
	if len(salt) != scryptSaltSize {
		return nil, headerError(fmt.Sprintf("the salt is %d bytes, not %d", len(salt), scryptSaltSize))
	}
	workFactor, err := parseWorkFactor(found.args[1], maxWorkFactor)
	if err != nil {
		return nil, fmt.Errorf("parse work factor: %w", err)
	}
	// Checked before any decryption is attempted, so that a body of the wrong
	// size is a malformed header rather than a wrong passphrase.
	if len(found.body) != wrappedKeySize {
		return nil, headerError(fmt.Sprintf("the wrapped key is %d bytes, not %d", len(found.body), wrappedKeySize))
	}

	key, err := scryptKey(passphrase, salt, workFactor)
	if err != nil {
		return nil, fmt.Errorf("scrypt key: %w", err)
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("chacha20poly1305 new: %w", err))
	}

	fileKey, err := aead.Open(nil, make([]byte, chacha20poly1305.NonceSize), found.body, noAdditionalData)
	if err != nil {
		return nil, altshiftErrors.NewWithTrace(ErrNoMatch)
	}

	return fileKey, nil
}
