// Package age encrypts and decrypts files in the age v1 format
// (https://c2sp.org/age), to a passphrase or to X25519 recipients.
//
// It implements the two recipient types of the specification's core, scrypt
// and X25519, and the binary encoding; the hybrid post-quantum recipients,
// plugins and the ASCII armor are left out. What it writes, the age command
// decrypts, and what the age command encrypts to a passphrase or an X25519
// recipient, this decrypts: the format is the specification's, so that the
// files outlive this code.
package age

import (
	"bufio"
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/empty_error"
	"github.com/altshiftab/utils_go/pkg/errors/types/nil_error"
)

const (
	// DefaultWorkFactor is the scrypt work factor the age command encrypts
	// with: 2^18 iterations, about a second and 256 MiB.
	DefaultWorkFactor = 18
	// MaxWorkFactor is the highest work factor the age command decrypts.
	MaxWorkFactor = 22

	fileKeySize = 16
)

// The classes of failure, as the specification's test vectors distinguish
// them. Every error returned while decrypting is one of these.
var (
	// ErrHeader is a header that does not parse.
	ErrHeader = errors.New("age: malformed header")
	// ErrNoMatch is a header with no stanza the passphrase unwraps.
	ErrNoMatch = errors.New("age: no stanza matched the passphrase")
	// ErrHmac is a header whose MAC does not match the unwrapped file key.
	ErrHmac = errors.New("age: header mac mismatch")
	// ErrPayload is a payload that does not decrypt, or that ends early or
	// late.
	ErrPayload = errors.New("age: payload failure")
	// ErrClosed is a write to a writer already closed.
	ErrClosed = errors.New("age: write to a closed writer")
)

// noAdditionalData is the format's: none. Spelled as an empty slice rather than
// nil for the nil-flow analysis, which follows a nil into the AEAD's assembly.
var noAdditionalData = []byte{}

// NewScryptWriter returns a writer that encrypts what is written to it to
// passphrase and writes the encrypted file to dst. Close completes the file;
// until it is called, the last chunk is still in memory and the file is
// truncated.
func NewScryptWriter(dst io.Writer, passphrase []byte, workFactor int) (io.WriteCloser, error) {
	if dst == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("dst"))
	}
	if len(passphrase) == 0 {
		return nil, altshiftErrors.NewWithTrace(empty_error.New("passphrase"))
	}
	if workFactor < 1 || workFactor > 30 {
		return nil, altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: work factor %d is out of range", altshiftErrors.ErrValidationError, workFactor),
		)
	}

	fileKey := make([]byte, fileKeySize)
	if _, err := rand.Read(fileKey); err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("rand read (file key): %w", err))
	}

	wrapped, err := wrapScrypt(fileKey, passphrase, workFactor)
	if err != nil {
		return nil, fmt.Errorf("wrap scrypt: %w", err)
	}

	headerBytes, err := marshalHeader(&header{stanzas: []*stanza{wrapped}}, fileKey)
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

// NewScryptReader reads the header of the encrypted file in src, unwraps its
// file key with passphrase, and returns a reader of the plaintext.
//
// The header is checked whole before anything is returned. The payload is
// checked a chunk at a time, and each chunk is released only once it has been
// authenticated; a read that fails partway has released only authentic
// plaintext, but not all of it, so a caller that needs the file whole must read
// to io.EOF before trusting any of it.
//
// maxWorkFactor bounds the scrypt work a file can demand; a header asking for
// more is refused before any is done.
func NewScryptReader(src io.Reader, passphrase []byte, maxWorkFactor int) (io.Reader, error) {
	if src == nil {
		return nil, altshiftErrors.NewWithTrace(nil_error.New("src"))
	}
	if len(passphrase) == 0 {
		return nil, altshiftErrors.NewWithTrace(empty_error.New("passphrase"))
	}

	buffered := bufio.NewReader(src)
	parsed, err := parseHeader(buffered)
	if err != nil {
		return nil, fmt.Errorf("parse header: %w", err)
	}

	fileKey, err := unwrapScrypt(parsed.stanzas, passphrase, maxWorkFactor)
	if err != nil {
		return nil, fmt.Errorf("unwrap scrypt: %w", err)
	}

	reader, err := openPayload(buffered, parsed, fileKey)
	if err != nil {
		return nil, fmt.Errorf("open payload: %w", err)
	}

	return reader, nil
}

// openPayload checks the header's MAC with the file key and returns a reader
// of the payload that follows the header in src.
func openPayload(src *bufio.Reader, parsed *header, fileKey []byte) (io.Reader, error) {
	if err := verifyHeaderMac(parsed, fileKey); err != nil {
		return nil, fmt.Errorf("verify header mac: %w", err)
	}

	reader, err := newStreamReader(src, fileKey)
	if err != nil {
		return nil, fmt.Errorf("new stream reader: %w", err)
	}

	return reader, nil
}
