package age

import (
	"bufio"
	"bytes"
	"compress/zlib"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// vector is one of the specification's test files: a few "key: value" lines,
// an empty line, and an age file.
type vector struct {
	name        string
	expect      string
	payloadHash string
	fileKey     []byte
	passphrases []string
	identities  []string
	armored     bool
	file        []byte
}

func readVector(t *testing.T, path string) *vector {
	t.Helper()

	data, err := os.ReadFile(path) //nolint:gosec // The path is one of the test's own files.
	if err != nil {
		t.Fatalf("os read file: %v", err)
	}

	textual, file, found := bytes.Cut(data, []byte("\n\n"))
	if !found {
		t.Fatalf("%s: no empty line after the textual header", path)
	}

	parsed := &vector{name: filepath.Base(path)}
	compressed := false
	for line := range strings.SplitSeq(string(textual), "\n") {
		key, value, found := strings.Cut(line, ": ")
		if !found {
			t.Fatalf("%s: bad textual header line %q", path, line)
		}

		switch key {
		case "expect":
			parsed.expect = value
		case "payload":
			parsed.payloadHash = value
		case "file key":
			if parsed.fileKey, err = hex.DecodeString(value); err != nil {
				t.Fatalf("%s: file key: %v", path, err)
			}
		case "passphrase":
			parsed.passphrases = append(parsed.passphrases, value)
		case "identity":
			parsed.identities = append(parsed.identities, value)
		case "armored":
			parsed.armored = value == "yes"
		case "compressed":
			compressed = value == "zlib"
		}
	}

	if compressed {
		reader, err := zlib.NewReader(bytes.NewReader(file))
		if err != nil {
			t.Fatalf("%s: zlib new reader: %v", path, err)
		}
		if file, err = io.ReadAll(reader); err != nil {
			t.Fatalf("%s: io read all (zlib): %v", path, err)
		}
	}
	parsed.file = file

	return parsed
}

// readReleased reads until an error, returning everything the reader released
// on the way: the specification checks even a failed decryption's output.
func readReleased(reader io.Reader) ([]byte, error) {
	var released bytes.Buffer
	buffer := make([]byte, 4096)
	for {
		n, err := reader.Read(buffer)
		released.Write(buffer[:n])
		if errors.Is(err, io.EOF) {
			return released.Bytes(), nil
		}
		if err != nil {
			return released.Bytes(), err
		}
	}
}

func classOf(err error) string {
	switch {
	case err == nil:
		return "success"
	case errors.Is(err, ErrHeader):
		return "header failure"
	case errors.Is(err, ErrNoMatch):
		return "no match"
	case errors.Is(err, ErrHmac):
		return "HMAC failure"
	case errors.Is(err, ErrPayload):
		return "payload failure"
	default:
		return "unclassified: " + err.Error()
	}
}

// x25519Identities parses the vector's X25519 identities, leaving out the
// hybrid post-quantum ones this package does not implement.
func x25519Identities(t *testing.T, testCase *vector) []*X25519Identity {
	t.Helper()

	var identities []*X25519Identity
	for _, encoded := range testCase.identities {
		if strings.HasPrefix(encoded, "AGE-SECRET-KEY-PQ-") {
			continue
		}
		identity, err := ParseX25519Identity(encoded)
		if err != nil {
			t.Fatalf("%s: parse x25519 identity: %v", testCase.name, err)
		}
		identities = append(identities, identity)
	}

	return identities
}

// TestVectors runs the specification's test files. Those that need a
// passphrase are decrypted through the scrypt API, and those that name an
// X25519 identity through the X25519 one. The rest are about the header's
// structure, its MAC and the payload rather than about a recipient, so they are
// opened with the file key each vector names, past a recipient type this
// package does not implement. Vectors that only a hybrid identity can open, and
// those about the armor, are skipped.
func TestVectors(t *testing.T) {
	t.Parallel()

	paths, err := filepath.Glob("testdata/cctv/*")
	if err != nil {
		t.Fatalf("filepath glob: %v", err)
	}

	ran := 0
	for _, path := range paths {
		if filepath.Base(path) == "LICENSE" {
			continue
		}
		testCase := readVector(t, path)
		identities := x25519Identities(t, testCase)

		recipientSpecific := strings.HasPrefix(testCase.name, "x25519") || strings.HasPrefix(testCase.name, "hybrid")
		if testCase.armored || (len(testCase.passphrases) == 0 && len(identities) == 0 && recipientSpecific) {
			continue
		}
		ran++

		var reader io.Reader
		switch {
		case len(testCase.passphrases) > 0:
			if len(testCase.passphrases) > 1 {
				// Only one passphrase is tried: the vectors that offer two
				// test that two stanzas are refused before either is tried.
				if testCase.expect != "header failure" {
					t.Errorf("%s: two passphrases for an outcome of %q", testCase.name, testCase.expect)
				}
			}
			reader, err = NewScryptReader(bytes.NewReader(testCase.file), []byte(testCase.passphrases[0]), MaxWorkFactor)
		case len(identities) > 0:
			reader, err = NewX25519Reader(bytes.NewReader(testCase.file), identities...)
		default:
			buffered := bufio.NewReader(bytes.NewReader(testCase.file))
			var parsed *header
			if parsed, err = parseHeader(buffered); err == nil {
				reader, err = openPayload(buffered, parsed, testCase.fileKey)
			}
		}

		var released []byte
		if err == nil {
			if reader == nil {
				t.Fatalf("%s: no reader and no error", testCase.name)
			}
			released, err = readReleased(reader)
		}

		if got := classOf(err); got != testCase.expect {
			t.Errorf("%s: got %s, want %s", testCase.name, got, testCase.expect)
		}
		if testCase.payloadHash != "" {
			sum := sha256.Sum256(released)
			if got := hex.EncodeToString(sum[:]); got != testCase.payloadHash {
				t.Errorf("%s: released %d bytes hashing to %s, want %s", testCase.name, len(released), got, testCase.payloadHash)
			}
		} else if len(released) != 0 {
			t.Errorf("%s: released %d bytes where none were expected", testCase.name, len(released))
		}
	}

	// Of the 147 vectors at the copied commit, 37 are armored and 17 more can
	// be opened only with a hybrid identity.
	if ran != 93 {
		t.Errorf("ran %d vectors, want 93: the copy in testdata has changed", ran)
	}
}
