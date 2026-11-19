package age

import (
	"bufio"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	chunkSize          = 64 << 10
	tagSize            = chacha20poly1305.Overhead
	encryptedChunkSize = chunkSize + tagSize
	payloadNonceSize   = 16
	// lastChunkFlag marks the final chunk in the last byte of its nonce, so a
	// payload cut short at a chunk boundary does not authenticate as whole.
	lastChunkFlag = 0x01
)

func payloadError(detail string) error {
	return altshiftErrors.NewWithTrace(fmt.Errorf("%w: %s", ErrPayload, detail))
}

func payloadErrorWith(detail string, cause error) error {
	return altshiftErrors.NewWithTrace(fmt.Errorf("%w: %s: %w", ErrPayload, detail, cause))
}

func newPayloadAead(fileKey []byte, nonce []byte) (cipher.AEAD, error) {
	key, err := hkdf.Key(sha256.New, fileKey, nonce, "payload", chacha20poly1305.KeySize)
	if err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("hkdf key (payload): %w", err))
	}

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("chacha20poly1305 new: %w", err))
	}

	return aead, nil
}

// chunkNonce is an eleven-byte big-endian chunk counter and the last-chunk
// flag.
type chunkNonce [chacha20poly1305.NonceSize]byte

func (n *chunkNonce) increment() error {
	for i := len(n) - 2; i >= 0; i-- {
		n[i]++
		if n[i] != 0 {
			return nil
		}
	}

	return payloadError("the chunk counter overflowed")
}

func (n *chunkNonce) setLast() {
	n[len(n)-1] = lastChunkFlag
}

func (n *chunkNonce) isFirst() bool {
	for _, b := range n[:len(n)-1] {
		if b != 0 {
			return false
		}
	}

	return true
}

type streamWriter struct {
	dst   io.Writer
	aead  cipher.AEAD
	nonce chunkNonce
	// buffer holds the plaintext of the chunk being filled, with room for its
	// tag so it can be sealed in place.
	buffer []byte
	err    error
}

func newStreamWriter(dst io.Writer, fileKey []byte) (*streamWriter, error) {
	nonce := make([]byte, payloadNonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("rand read (payload nonce): %w", err))
	}

	aead, err := newPayloadAead(fileKey, nonce)
	if err != nil {
		return nil, fmt.Errorf("new payload aead: %w", err)
	}

	if _, err := dst.Write(nonce); err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("write (payload nonce): %w", err))
	}

	return &streamWriter{dst: dst, aead: aead, buffer: make([]byte, 0, encryptedChunkSize)}, nil
}

func (w *streamWriter) Write(p []byte) (int, error) {
	if w.err != nil {
		return 0, w.err
	}

	total := 0
	for len(p) > 0 {
		// A full chunk is sealed only once more data shows it is not the last:
		// sealed eagerly, a payload that fills its chunks exactly would end in
		// an empty final chunk, which the format forbids.
		if len(w.buffer) == chunkSize {
			if err := w.seal(false); err != nil {
				w.err = err
				return total, fmt.Errorf("seal: %w", err)
			}
		}

		n := copy(w.buffer[len(w.buffer):chunkSize], p)
		w.buffer = w.buffer[:len(w.buffer)+n]
		p = p[n:]
		total += n
	}

	return total, nil
}

// Close seals the last chunk. The file is complete only once it returns
// without error.
func (w *streamWriter) Close() error {
	if w.err != nil {
		return w.err
	}

	err := w.seal(true)
	if err != nil {
		w.err = err
		return fmt.Errorf("seal: %w", err)
	}
	w.err = altshiftErrors.NewWithTrace(ErrClosed)

	return nil
}

func (w *streamWriter) seal(last bool) error {
	if last {
		w.nonce.setLast()
	}

	sealed := w.aead.Seal(w.buffer[:0], w.nonce[:], w.buffer, noAdditionalData)
	if _, err := w.dst.Write(sealed); err != nil {
		return altshiftErrors.NewWithTrace(fmt.Errorf("write (chunk): %w", err))
	}
	w.buffer = w.buffer[:0]

	if err := w.nonce.increment(); err != nil {
		return fmt.Errorf("increment: %w", err)
	}

	return nil
}

type streamReader struct {
	src   *bufio.Reader
	aead  cipher.AEAD
	nonce chunkNonce
	// encrypted and plain are separate: a failed open clears its output, and
	// the ciphertext may have to be opened a second time as the last chunk.
	encrypted []byte
	plain     []byte
	unread    []byte
	err       error
}

func newStreamReader(src *bufio.Reader, fileKey []byte) (*streamReader, error) {
	nonce := make([]byte, payloadNonceSize)
	if _, err := io.ReadFull(src, nonce); err != nil {
		// The specification counts the nonce as part of the header.
		return nil, headerErrorWith("payload nonce: io read full", err)
	}

	aead, err := newPayloadAead(fileKey, nonce)
	if err != nil {
		return nil, fmt.Errorf("new payload aead: %w", err)
	}

	return &streamReader{
		src:       src,
		aead:      aead,
		encrypted: make([]byte, encryptedChunkSize),
		plain:     make([]byte, 0, chunkSize),
	}, nil
}

func (r *streamReader) Read(p []byte) (int, error) {
	if len(r.unread) > 0 {
		n := copy(p, r.unread)
		r.unread = r.unread[n:]
		return n, nil
	}
	if r.err != nil {
		return 0, r.err
	}
	if len(p) == 0 {
		return 0, nil
	}

	last, err := r.readChunk()
	if err != nil {
		r.err = err
		return 0, err
	}

	n := copy(p, r.unread)
	r.unread = r.unread[n:]

	if last {
		// The last chunk must be followed by nothing at all.
		switch _, err := r.src.ReadByte(); {
		case err == nil:
			r.err = payloadError("data follows the last chunk")
		case errors.Is(err, io.EOF):
			r.err = io.EOF
		default:
			r.err = payloadErrorWith("read byte (after the last chunk)", err)
		}
	}

	return n, nil
}

// readChunk opens the next chunk into unread and reports whether it was the
// last.
func (r *streamReader) readChunk() (bool, error) {
	encrypted := r.encrypted
	n, err := io.ReadFull(r.src, encrypted)

	last := false
	switch {
	case errors.Is(err, io.EOF):
		return false, payloadError("the payload ends without a last chunk")
	case errors.Is(err, io.ErrUnexpectedEOF):
		// A short chunk can only be the last. It can be empty only when it is
		// also the first: a payload whose last chunk is empty would have been
		// written as a full one.
		if n < tagSize {
			return false, payloadError("a chunk is shorter than its tag")
		}
		if n == tagSize && !r.nonce.isFirst() {
			return false, payloadError("the last chunk is empty")
		}
		encrypted = encrypted[:n]
		last = true
		r.nonce.setLast()
	case err != nil:
		return false, payloadErrorWith("io read full", err)
	}

	plain, err := r.aead.Open(r.plain[:0], r.nonce[:], encrypted, noAdditionalData)
	if err != nil && !last {
		// A full chunk can be the last one too.
		last = true
		r.nonce.setLast()
		plain, err = r.aead.Open(r.plain[:0], r.nonce[:], encrypted, noAdditionalData)
	}
	if err != nil {
		return false, payloadError("a chunk does not authenticate")
	}

	if err := r.nonce.increment(); err != nil {
		return false, fmt.Errorf("increment: %w", err)
	}
	r.unread = plain

	return last, nil
}
