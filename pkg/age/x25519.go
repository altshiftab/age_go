package age

import (
	"bufio"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"strings"

	"github.com/altshiftab/age_go/pkg/bech32"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/empty_error"
	"github.com/altshiftab/utils_go/pkg/errors/types/nil_error"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	x25519Kind    = "X25519"
	x25519Label   = "age-encryption.org/v1/X25519"
	x25519KeySize = 32

	// The human-readable parts of a recipient and an identity, in the lower
	// case bech32 decodes to. An identity is written in upper case.
	recipientHrp = "age"
	identityHrp  = "age-secret-key-"
)

// X25519Recipient is a public key a file can be encrypted to: the half of an
// identity that can be given out, written "age1…".
type X25519Recipient struct {
	publicKey *ecdh.PublicKey
}

// ParseX25519Recipient reads a recipient as age writes it, "age1" and 58 more
// characters.
func ParseX25519Recipient(s string) (*X25519Recipient, error) {
	if s == "" {
		return nil, altshiftErrors.NewWithTrace(empty_error.New("recipient"))
	}

	hrp, data, err := bech32.Decode(s)
	if err != nil {
		return nil, fmt.Errorf("bech32 decode: %w", err)
	}
	if hrp != recipientHrp {
		return nil, altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: a recipient starts with %q, not %q", altshiftErrors.ErrParseError, hrp, recipientHrp),
		)
	}
	if len(data) != x25519KeySize {
		return nil, altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: a recipient is %d bytes, not %d", altshiftErrors.ErrParseError, len(data), x25519KeySize),
		)
	}

	publicKey, err := ecdh.X25519().NewPublicKey(data)
	if err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("%w: ecdh x25519 new public key: %w", altshiftErrors.ErrParseError, err))
	}

	return &X25519Recipient{publicKey: publicKey}, nil
}

// String writes the recipient as age does.
func (r *X25519Recipient) String() string {
	if r == nil || r.publicKey == nil {
		return ""
	}

	// The human-readable part is a constant Encode accepts, so it cannot fail.
	encoded, err := bech32.Encode(recipientHrp, r.publicKey.Bytes())
	if err != nil {
		return ""
	}

	return encoded
}

// X25519Identity is a private key that decrypts what was encrypted to its
// recipient, written "AGE-SECRET-KEY-1…".
type X25519Identity struct {
	privateKey *ecdh.PrivateKey
}

// GenerateX25519Identity makes a new identity, as age-keygen does.
func GenerateX25519Identity() (*X25519Identity, error) {
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("ecdh x25519 generate key: %w", err))
	}

	return &X25519Identity{privateKey: privateKey}, nil
}

// ParseX25519Identity reads an identity as age-keygen writes it,
// "AGE-SECRET-KEY-1" and 58 more characters.
func ParseX25519Identity(s string) (*X25519Identity, error) {
	if s == "" {
		return nil, altshiftErrors.NewWithTrace(empty_error.New("identity"))
	}

	hrp, data, err := bech32.Decode(s)
	if err != nil {
		return nil, fmt.Errorf("bech32 decode: %w", err)
	}
	if hrp != identityHrp {
		// Not the decoded string: it would be most of a secret key.
		return nil, altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: an identity does not start with %q", altshiftErrors.ErrParseError, strings.ToUpper(identityHrp)),
		)
	}
	if len(data) != x25519KeySize {
		return nil, altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: an identity is %d bytes, not %d", altshiftErrors.ErrParseError, len(data), x25519KeySize),
		)
	}

	privateKey, err := ecdh.X25519().NewPrivateKey(data)
	if err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("%w: ecdh x25519 new private key: %w", altshiftErrors.ErrParseError, err))
	}

	return &X25519Identity{privateKey: privateKey}, nil
}

// Recipient returns the identity's public half.
func (i *X25519Identity) Recipient() *X25519Recipient {
	if i == nil || i.privateKey == nil {
		return nil
	}

	return &X25519Recipient{publicKey: i.privateKey.PublicKey()}
}

// String writes the identity as age-keygen does. It is the secret key: keep it
// out of logs.
func (i *X25519Identity) String() string {
	if i == nil || i.privateKey == nil {
		return ""
	}

	encoded, err := bech32.Encode(identityHrp, i.privateKey.Bytes())
	if err != nil {
		return ""
	}

	return strings.ToUpper(encoded)
}

// x25519WrapKey derives the key a file key is sealed under from the shared
// secret, salted with both public halves: the ephemeral share, then the
// recipient.
func x25519WrapKey(sharedSecret []byte, share []byte, recipient []byte) ([]byte, error) {
	salt := make([]byte, 0, len(share)+len(recipient))
	salt = append(salt, share...)
	salt = append(salt, recipient...)

	key, err := hkdf.Key(sha256.New, sharedSecret, salt, x25519Label, chacha20poly1305.KeySize)
	if err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("hkdf key (x25519): %w", err))
	}

	return key, nil
}

// wrapX25519 seals the file key to one recipient, under a fresh ephemeral key.
func wrapX25519(fileKey []byte, recipient *X25519Recipient) (*stanza, error) {
	if recipient == nil || recipient.publicKey == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("recipient"))
	}

	ephemeral, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("ecdh x25519 generate key (ephemeral): %w", err))
	}
	share := ephemeral.PublicKey().Bytes()

	// Refused for a low-order recipient, whose shared secret would be zero.
	sharedSecret, err := ephemeral.ECDH(recipient.publicKey)
	if err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("%w: ecdh: %w", altshiftErrors.ErrValidationError, err))
	}

	key, err := x25519WrapKey(sharedSecret, share, recipient.publicKey.Bytes())
	if err != nil {
		return nil, fmt.Errorf("x25519 wrap key: %w", err)
	}

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("chacha20poly1305 new: %w", err))
	}

	// The key is derived for this one seal, so a nonce of zeros is safe.
	body := aead.Seal(nil, make([]byte, chacha20poly1305.NonceSize), fileKey, noAdditionalData)

	return &stanza{kind: x25519Kind, args: []string{b64.EncodeToString(share)}, body: body}, nil
}

// unwrapX25519 opens the file key from the first X25519 stanza one of the
// identities matches.
//
// Every X25519 stanza is checked before it is tried, and a malformed one is a
// malformed header even if a later stanza would have matched. Stanzas of other
// kinds are passed over, as the specification asks of a recipient type a
// decrypter does not know, except scrypt, which is meant to be a file's only
// key and is refused beside anything else.
func unwrapX25519(stanzas []*stanza, identities []*X25519Identity) ([]byte, error) {
	for _, s := range stanzas {
		if s.kind == scryptKind && len(stanzas) != 1 {
			return nil, headerError("a scrypt stanza is not alone in the header")
		}
	}

	for _, s := range stanzas {
		if s.kind != x25519Kind {
			continue
		}

		if len(s.args) != 1 {
			return nil, headerError(fmt.Sprintf("an X25519 stanza has %d arguments, not 1", len(s.args)))
		}
		share, err := decodeB64(s.args[0])
		if err != nil {
			return nil, fmt.Errorf("decode b64 (share): %w", err)
		}
		if len(share) != x25519KeySize {
			return nil, headerError(fmt.Sprintf("an X25519 share is %d bytes, not %d", len(share), x25519KeySize))
		}
		if len(s.body) != wrappedKeySize {
			return nil, headerError(fmt.Sprintf("an X25519 wrapped key is %d bytes, not %d", len(s.body), wrappedKeySize))
		}
		sharePublicKey, err := ecdh.X25519().NewPublicKey(share)
		if err != nil {
			return nil, headerErrorWith("ecdh x25519 new public key (share)", err)
		}

		for _, identity := range identities {
			// A share of low order gives a shared secret of zero, which the
			// specification has refused as a malformed header.
			sharedSecret, err := identity.privateKey.ECDH(sharePublicKey)
			if err != nil {
				return nil, headerErrorWith("ecdh", err)
			}

			key, err := x25519WrapKey(sharedSecret, share, identity.privateKey.PublicKey().Bytes())
			if err != nil {
				return nil, fmt.Errorf("x25519 wrap key: %w", err)
			}
			aead, err := chacha20poly1305.New(key)
			if err != nil {
				return nil, altshiftErrors.NewWithTrace(fmt.Errorf("chacha20poly1305 new: %w", err))
			}

			fileKey, err := aead.Open(nil, make([]byte, chacha20poly1305.NonceSize), s.body, noAdditionalData)
			if err != nil {
				// Sealed to someone else.
				continue
			}

			return fileKey, nil
		}
	}

	return nil, altshiftErrors.NewWithTrace(ErrNoMatch)
}

// NewX25519Writer returns a writer that encrypts what is written to it to the
// recipients, any of whose identities can decrypt it, and writes the encrypted
// file to dst. Close completes the file; until it is called, the last chunk is
// still in memory and the file is truncated.
func NewX25519Writer(dst io.Writer, recipients ...*X25519Recipient) (io.WriteCloser, error) {
	if dst == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("dst"))
	}
	if len(recipients) == 0 {
		return nil, altshiftErrors.NewWithTrace(empty_error.New("recipients"))
	}

	fileKey := make([]byte, fileKeySize)
	if _, err := rand.Read(fileKey); err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("rand read (file key): %w", err))
	}

	stanzas := make([]*stanza, 0, len(recipients))
	for _, recipient := range recipients {
		wrapped, err := wrapX25519(fileKey, recipient)
		if err != nil {
			return nil, fmt.Errorf("wrap x25519: %w", err)
		}
		stanzas = append(stanzas, wrapped)
	}

	headerBytes, err := marshalHeader(&header{stanzas: stanzas}, fileKey)
	if err != nil {
		return nil, fmt.Errorf("marshal header: %w", err)
	}
	if _, err := dst.Write(headerBytes); err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("write (header): %w", err))
	}

	writer, err := newStreamWriter(dst, fileKey)
	if err != nil {
		return nil, fmt.Errorf("new stream writer: %w", err)
	}

	return writer, nil
}

// NewX25519Reader reads the header of the encrypted file in src, unwraps its
// file key with whichever of the identities it was encrypted to, and returns a
// reader of the plaintext.
//
// The header is checked whole before anything is returned, and the payload is
// released a chunk at a time, each only after it has been authenticated, as by
// NewScryptReader: a caller that needs the file whole must read to io.EOF
// before trusting any of it.
func NewX25519Reader(src io.Reader, identities ...*X25519Identity) (io.Reader, error) {
	if src == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("src"))
	}
	if len(identities) == 0 {
		return nil, altshiftErrors.NewWithTrace(empty_error.New("identities"))
	}
	for _, identity := range identities {
		if identity == nil || identity.privateKey == nil {
			return nil, altshiftErrors.NewWithTrace(nil_error.New("identity"))
		}
	}

	buffered := bufio.NewReader(src)
	parsed, err := parseHeader(buffered)
	if err != nil {
		return nil, fmt.Errorf("parse header: %w", err)
	}

	fileKey, err := unwrapX25519(parsed.stanzas, identities)
	if err != nil {
		return nil, fmt.Errorf("unwrap x25519: %w", err)
	}

	reader, err := openPayload(buffered, parsed, fileKey)
	if err != nil {
		return nil, fmt.Errorf("open payload: %w", err)
	}

	return reader, nil
}
