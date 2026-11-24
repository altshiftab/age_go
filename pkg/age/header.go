package age

import (
	"bufio"
	"bytes"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
)

const (
	versionLine  = "age-encryption.org/v1"
	stanzaPrefix = "-> "
	footerPrefix = "---"
	// columnsPerLine is the width a stanza body's base64 is wrapped at; the
	// last line of a body is always shorter, and empty when the body fills its
	// lines exactly.
	columnsPerLine = 64
	macSize        = sha256.Size
	// maxHeaderSize bounds what is read looking for the end of a header.
	maxHeaderSize = 1 << 20
)

// b64 is the base64 the format uses throughout: the standard alphabet, no
// padding, and no stray bits in the last character, so that every value has
// exactly one encoding.
var b64 = base64.RawStdEncoding.Strict()

type stanza struct {
	kind string
	args []string
	body []byte
}

type header struct {
	stanzas []*stanza
	// covered is the header as read, from the version line up to and including
	// the "---" that starts the footer: what the MAC is computed over.
	covered []byte
	mac     []byte
}

func headerError(detail string) error {
	return altshiftErrors.NewWithTrace(fmt.Errorf("%w: %s", ErrHeader, detail))
}

func headerErrorWith(detail string, cause error) error {
	return altshiftErrors.NewWithTrace(fmt.Errorf("%w: %s: %w", ErrHeader, detail, cause))
}

// isBase64 reports whether s is drawn from the base64 alphabet alone. The
// decoder is not enough on its own: it skips carriage returns and newlines,
// which the format forbids.
func isBase64(s string) bool {
	for i := range len(s) {
		switch c := s[i]; {
		case 'A' <= c && c <= 'Z', 'a' <= c && c <= 'z', '0' <= c && c <= '9', c == '+', c == '/':
		default:
			return false
		}
	}

	return true
}

func decodeB64(s string) ([]byte, error) {
	if !isBase64(s) {
		return nil, headerError(fmt.Sprintf("%q is not in the base64 alphabet", s))
	}

	decoded, err := b64.DecodeString(s)
	if err != nil {
		return nil, headerErrorWith("base64 decode string", err)
	}

	return decoded, nil
}

// isArgument reports whether s is a stanza argument: one or more visible
// ASCII characters.
func isArgument(s string) bool {
	if s == "" {
		return false
	}
	for i := range len(s) {
		if s[i] < 0x21 || s[i] > 0x7e {
			return false
		}
	}

	return true
}

type lineReader struct {
	src  *bufio.Reader
	read []byte
}

// next returns the next line without its newline, keeping it in read.
func (r *lineReader) next() (string, error) {
	line, err := r.src.ReadSlice('\n')
	if err != nil {
		if errors.Is(err, bufio.ErrBufferFull) {
			return "", headerError("a line is too long")
		}
		return "", headerErrorWith("read slice", err)
	}

	r.read = append(r.read, line...)
	if len(r.read) > maxHeaderSize {
		return "", headerError(fmt.Sprintf("the header is longer than %d bytes", maxHeaderSize))
	}

	return string(line[:len(line)-1]), nil
}

// parseHeader reads a header from src, leaving src at the first byte of the
// payload.
func parseHeader(src *bufio.Reader) (*header, error) {
	lines := &lineReader{src: src}

	version, err := lines.next()
	if err != nil {
		return nil, fmt.Errorf("next (version): %w", err)
	}
	if version != versionLine {
		return nil, headerError(fmt.Sprintf("unsupported version %q", version))
	}

	parsed := &header{}
	for {
		line, err := lines.next()
		if err != nil {
			return nil, fmt.Errorf("next: %w", err)
		}

		if rest, found := strings.CutPrefix(line, footerPrefix); found {
			// The format requires at least one stanza, and the reference implementation refuses a header with none.
			if len(parsed.stanzas) == 0 {
				return nil, headerError("the header has no stanza")
			}
			macString, found := strings.CutPrefix(rest, " ")
			if !found {
				return nil, headerError("the footer has no space before its mac")
			}
			mac, err := decodeB64(macString)
			if err != nil {
				return nil, fmt.Errorf("decode b64 (mac): %w", err)
			}
			if len(mac) != macSize {
				return nil, headerError(fmt.Sprintf("the mac is %d bytes", len(mac)))
			}

			parsed.mac = mac
			// Everything read, short of this line's " <mac>\n".
			parsed.covered = lines.read[:len(lines.read)-len(rest)-1]
			return parsed, nil
		}

		argumentLine, found := strings.CutPrefix(line, stanzaPrefix)
		if !found {
			return nil, headerError("a line is neither a stanza nor the footer")
		}

		arguments := strings.Split(argumentLine, " ")
		for _, argument := range arguments {
			if !isArgument(argument) {
				return nil, headerError("a stanza argument is empty or has an invalid character")
			}
		}

		body, err := readBody(lines)
		if err != nil {
			return nil, fmt.Errorf("read body: %w", err)
		}

		parsed.stanzas = append(parsed.stanzas, &stanza{kind: arguments[0], args: arguments[1:], body: body})
	}
}

// readBody reads a stanza body: full lines of base64, ended by a shorter one.
func readBody(lines *lineReader) ([]byte, error) {
	var encoded strings.Builder
	for {
		line, err := lines.next()
		if err != nil {
			return nil, fmt.Errorf("next (body): %w", err)
		}
		if len(line) > columnsPerLine {
			return nil, headerError(fmt.Sprintf("a body line is longer than %d columns", columnsPerLine))
		}
		if !isBase64(line) {
			return nil, headerError("a body line is not base64")
		}

		encoded.WriteString(line)
		if len(line) < columnsPerLine {
			break
		}
	}

	body, err := decodeB64(encoded.String())
	if err != nil {
		return nil, fmt.Errorf("decode b64 (body): %w", err)
	}

	return body, nil
}

func headerMac(covered []byte, fileKey []byte) ([]byte, error) {
	key, err := hkdf.Key(sha256.New, fileKey, nil, "header", sha256.Size)
	if err != nil {
		return nil, altshiftErrors.NewWithTrace(fmt.Errorf("hkdf key (header): %w", err))
	}

	mac := hmac.New(sha256.New, key)
	mac.Write(covered)

	return mac.Sum(nil), nil
}

func verifyHeaderMac(parsed *header, fileKey []byte) error {
	mac, err := headerMac(parsed.covered, fileKey)
	if err != nil {
		return fmt.Errorf("header mac: %w", err)
	}
	if !hmac.Equal(mac, parsed.mac) {
		return altshiftErrors.NewWithTrace(ErrHmac)
	}

	return nil
}

// marshalHeader encodes a header and its MAC under fileKey.
func marshalHeader(h *header, fileKey []byte) ([]byte, error) {
	var buffer bytes.Buffer
	buffer.WriteString(versionLine + "\n")

	for _, s := range h.stanzas {
		buffer.WriteString(stanzaPrefix + s.kind)
		for _, argument := range s.args {
			buffer.WriteString(" " + argument)
		}
		buffer.WriteString("\n")

		encoded := b64.EncodeToString(s.body)
		for len(encoded) >= columnsPerLine {
			buffer.WriteString(encoded[:columnsPerLine] + "\n")
			encoded = encoded[columnsPerLine:]
		}
		buffer.WriteString(encoded + "\n")
	}

	buffer.WriteString(footerPrefix)
	mac, err := headerMac(buffer.Bytes(), fileKey)
	if err != nil {
		return nil, fmt.Errorf("header mac: %w", err)
	}
	buffer.WriteString(" " + b64.EncodeToString(mac) + "\n")

	return buffer.Bytes(), nil
}
