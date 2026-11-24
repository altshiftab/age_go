package age

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"slices"
	"testing"

	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
)

// testWorkFactor keeps scrypt quick; the format is the same at any factor.
const testWorkFactor = 10

var testPassphrase = []byte("correct horse battery staple")

func randomPlaintext(t *testing.T, n int) []byte {
	t.Helper()

	data := make([]byte, n)
	if _, err := rand.Read(data); err != nil {
		t.Fatalf("rand read: %v", err)
	}

	return data
}

func encrypt(t *testing.T, plaintext []byte, writeSize int) []byte {
	t.Helper()

	var encrypted bytes.Buffer
	writer, err := NewScryptWriter(&encrypted, testPassphrase, testWorkFactor)
	if err != nil {
		t.Fatalf("new scrypt writer: %v", err)
	}
	for rest := plaintext; len(rest) > 0; {
		n := min(writeSize, len(rest))
		if _, err := writer.Write(rest[:n]); err != nil {
			t.Fatalf("write: %v", err)
		}
		rest = rest[n:]
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	return encrypted.Bytes()
}

func decrypt(encrypted []byte, passphrase []byte, maxWorkFactor int) ([]byte, error) {
	reader, err := NewScryptReader(bytes.NewReader(encrypted), passphrase, maxWorkFactor)
	if err != nil {
		return nil, err
	}

	return readReleased(reader)
}

// headerLength is where the payload nonce starts.
func headerLength(t *testing.T, encrypted []byte) int {
	t.Helper()

	buffered := bufio.NewReader(bytes.NewReader(encrypted))
	if _, err := parseHeader(buffered); err != nil {
		t.Fatalf("parse header: %v", err)
	}

	// What the reader still holds, buffered or not, is what follows the header.
	rest, err := io.ReadAll(buffered)
	if err != nil {
		t.Fatalf("io read all: %v", err)
	}

	return len(encrypted) - len(rest)
}

func TestRoundTrip(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name      string
		size      int
		writeSize int
		// wantChunks is how many chunks the payload is sealed in.
		wantChunks int
	}{
		{name: "empty", size: 0, writeSize: 1, wantChunks: 1},
		{name: "one byte", size: 1, writeSize: 1, wantChunks: 1},
		{name: "a chunk less one", size: chunkSize - 1, writeSize: 1000, wantChunks: 1},
		{name: "exactly a chunk", size: chunkSize, writeSize: chunkSize, wantChunks: 1},
		{name: "a chunk and one", size: chunkSize + 1, writeSize: 7, wantChunks: 2},
		{name: "exactly two chunks", size: 2 * chunkSize, writeSize: 2 * chunkSize, wantChunks: 2},
		{name: "two chunks and one", size: 2*chunkSize + 1, writeSize: 65_537, wantChunks: 3},
		{name: "written in one call", size: 5*chunkSize + 123, writeSize: 5*chunkSize + 123, wantChunks: 6},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			plaintext := randomPlaintext(t, testCase.size)
			encrypted := encrypt(t, plaintext, testCase.writeSize)

			// A chunk count off by one is the writer sealing eagerly: an empty
			// final chunk after a payload that fills its chunks exactly.
			wantLength := headerLength(t, encrypted) + payloadNonceSize + testCase.size + testCase.wantChunks*tagSize
			if len(encrypted) != wantLength {
				t.Errorf("encrypted is %d bytes, want %d", len(encrypted), wantLength)
			}

			decrypted, err := decrypt(encrypted, testPassphrase, MaxWorkFactor)
			if err != nil {
				t.Fatalf("decrypt: %v", err)
			}
			if !bytes.Equal(decrypted, plaintext) {
				t.Errorf("decrypted %d bytes that differ from the %d encrypted", len(decrypted), len(plaintext))
			}
		})
	}
}

// TestTampered changes a three-chunk file in the ways an attacker or a broken
// disk would, and checks both how decryption fails and that what it released
// before failing was a true prefix of the plaintext.
func TestTampered(t *testing.T) {
	t.Parallel()

	plaintext := randomPlaintext(t, 2*chunkSize+1000)
	encrypted := encrypt(t, plaintext, len(plaintext))
	nonceStart := headerLength(t, encrypted)
	chunkStart := func(i int) int { return nonceStart + payloadNonceSize + i*encryptedChunkSize }
	macStart := bytes.Index(encrypted, []byte("\n--- ")) + len("\n--- ")
	bodyStart := bytes.Index(encrypted, []byte("\n-> ")) + 1
	bodyStart += bytes.IndexByte(encrypted[bodyStart:], '\n') + 1

	flip := func(offset int) func([]byte) []byte {
		return func(file []byte) []byte {
			file[offset] ^= 0x01
			return file
		}
	}
	// swapBase64 replaces a base64 character with another valid one, so that
	// the header still parses and only the value changes.
	swapBase64 := func(offset int) func([]byte) []byte {
		return func(file []byte) []byte {
			if file[offset] == 'A' {
				file[offset] = 'B'
			} else {
				file[offset] = 'A'
			}
			return file
		}
	}
	truncate := func(length int) func([]byte) []byte {
		return func(file []byte) []byte { return file[:length] }
	}

	testCases := []struct {
		name   string
		mutate func([]byte) []byte
		want   error
		// wantReleased is how much plaintext comes out before the failure.
		wantReleased int
	}{
		{name: "version line", mutate: flip(3), want: ErrHeader},
		{name: "stanza body", mutate: swapBase64(bodyStart), want: ErrNoMatch},
		{name: "mac", mutate: swapBase64(macStart), want: ErrHmac},
		{name: "truncated in the header", mutate: truncate(macStart), want: ErrHeader},
		{name: "truncated in the nonce", mutate: truncate(nonceStart + 5), want: ErrHeader},
		{name: "nonce", mutate: flip(nonceStart), want: ErrPayload},
		{name: "first chunk", mutate: flip(chunkStart(0) + 10), want: ErrPayload},
		{name: "second chunk's tag", mutate: flip(chunkStart(2) - 1), want: ErrPayload, wantReleased: chunkSize},
		{name: "last chunk", mutate: flip(chunkStart(2) + 3), want: ErrPayload, wantReleased: 2 * chunkSize},
		{name: "truncated after the first chunk", mutate: truncate(chunkStart(1)), want: ErrPayload, wantReleased: chunkSize},
		{name: "truncated after the second chunk", mutate: truncate(chunkStart(2)), want: ErrPayload, wantReleased: 2 * chunkSize},
		{name: "truncated in the second chunk", mutate: truncate(chunkStart(1) + 100), want: ErrPayload, wantReleased: chunkSize},
		{name: "truncated by one byte", mutate: truncate(len(encrypted) - 1), want: ErrPayload, wantReleased: 2 * chunkSize},
		{name: "no payload", mutate: truncate(chunkStart(0)), want: ErrPayload},
		{
			name: "no stanza",
			mutate: func(file []byte) []byte {
				versionEnd := bytes.IndexByte(file, '\n') + 1
				return append(slices.Clone(file[:versionEnd]), file[macStart-len("--- "):]...)
			},
			want: ErrHeader,
		},
		{
			name: "first two chunks swapped",
			mutate: func(file []byte) []byte {
				first := slices.Clone(file[chunkStart(0):chunkStart(1)])
				copy(file[chunkStart(0):], file[chunkStart(1):chunkStart(2)])
				copy(file[chunkStart(1):], first)
				return file
			},
			want: ErrPayload,
		},
		{
			name: "second chunk repeated",
			mutate: func(file []byte) []byte {
				second := slices.Clone(file[chunkStart(1):chunkStart(2)])
				return slices.Insert(file, chunkStart(2), second...)
			},
			want:         ErrPayload,
			wantReleased: 2 * chunkSize,
		},
		{
			name:         "a byte appended",
			mutate:       func(file []byte) []byte { return append(file, 0) },
			want:         ErrPayload,
			wantReleased: 2 * chunkSize,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			tampered := testCase.mutate(slices.Clone(encrypted))
			released, err := decrypt(tampered, testPassphrase, MaxWorkFactor)
			if !errors.Is(err, testCase.want) {
				t.Errorf("err = %v, want %v", err, testCase.want)
			}
			if len(released) != testCase.wantReleased {
				t.Errorf("released %d bytes, want %d", len(released), testCase.wantReleased)
			}
			if !bytes.HasPrefix(plaintext, released) {
				t.Errorf("released bytes that are not the plaintext's")
			}
		})
	}
}

func TestDecryptRefuses(t *testing.T) {
	t.Parallel()

	encrypted := encrypt(t, []byte("hello"), 5)

	testCases := []struct {
		name          string
		passphrase    []byte
		maxWorkFactor int
		want          error
	}{
		{name: "wrong passphrase", passphrase: []byte("wrong"), maxWorkFactor: MaxWorkFactor, want: ErrNoMatch},
		{name: "work factor above the limit", passphrase: testPassphrase, maxWorkFactor: testWorkFactor - 1, want: ErrHeader},
		{name: "a limit of zero", passphrase: testPassphrase, maxWorkFactor: 0, want: altshiftErrors.ErrValidationError},
		{name: "a limit past what scrypt can do", passphrase: testPassphrase, maxWorkFactor: 64, want: altshiftErrors.ErrValidationError},
		{name: "right passphrase", passphrase: testPassphrase, maxWorkFactor: testWorkFactor, want: nil},
	}

	for _, testCase := range testCases {
		_, err := decrypt(encrypted, testCase.passphrase, testCase.maxWorkFactor)
		if !errors.Is(err, testCase.want) {
			t.Errorf("%s: err = %v, want %v", testCase.name, err, testCase.want)
		}
	}
}

func TestHeaderRoundTrip(t *testing.T) {
	t.Parallel()

	fileKey := randomPlaintext(t, fileKeySize)

	// 48 bytes fill a 64-column line exactly, which must be followed by an
	// empty one.
	for _, bodySize := range []int{0, 1, 47, 48, 49, 96, 100} {
		original := &header{stanzas: []*stanza{
			{kind: "grease", args: []string{"a", "~!@"}, body: randomPlaintext(t, bodySize)},
			{kind: "other", body: randomPlaintext(t, 3)},
		}}

		encoded, err := marshalHeader(original, fileKey)
		if err != nil {
			t.Fatalf("marshal header: %v", err)
		}

		parsed, err := parseHeader(bufio.NewReader(bytes.NewReader(encoded)))
		if err != nil {
			t.Fatalf("body of %d: parse header: %v", bodySize, err)
		}
		if err := verifyHeaderMac(parsed, fileKey); err != nil {
			t.Errorf("body of %d: verify header mac: %v", bodySize, err)
		}
		if len(parsed.stanzas) != len(original.stanzas) {
			t.Fatalf("body of %d: %d stanzas, want %d", bodySize, len(parsed.stanzas), len(original.stanzas))
		}
		for i, s := range parsed.stanzas {
			want := original.stanzas[i]
			if s.kind != want.kind || !slices.Equal(s.args, want.args) || !bytes.Equal(s.body, want.body) {
				t.Errorf("body of %d: stanza %d did not survive", bodySize, i)
			}
		}
	}
}

// TestHeaderRejectsStrayCharacters covers what the base64 decoder would let
// through on its own: it skips carriage returns and newlines.
func TestHeaderRejectsStrayCharacters(t *testing.T) {
	t.Parallel()

	encrypted := encrypt(t, []byte("hello"), 5)
	footerEnd := bytes.Index(encrypted, []byte("\n--- ")) + 1
	footerEnd += bytes.IndexByte(encrypted[footerEnd:], '\n')

	testCases := []struct {
		name   string
		mutate func([]byte) []byte
	}{
		{
			name:   "carriage return before the mac's newline",
			mutate: func(file []byte) []byte { return slices.Insert(file, footerEnd, '\r') },
		},
		{
			name:   "carriage return inside the mac",
			mutate: func(file []byte) []byte { return slices.Insert(file, footerEnd-10, '\r') },
		},
		{
			name:   "padding after the mac",
			mutate: func(file []byte) []byte { return slices.Insert(file, footerEnd, '=') },
		},
	}

	for _, testCase := range testCases {
		_, err := decrypt(testCase.mutate(slices.Clone(encrypted)), testPassphrase, MaxWorkFactor)
		if !errors.Is(err, ErrHeader) {
			t.Errorf("%s: err = %v, want a header error", testCase.name, err)
		}
	}
}

func TestParseWorkFactor(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name  string
		value string
		want  int
		fails bool
	}{
		{name: "plain", value: "18", want: 18},
		{name: "the limit", value: "22", want: 22},
		{name: "above the limit", value: "23", fails: true},
		{name: "zero", value: "0", fails: true},
		{name: "leading zero", value: "018", fails: true},
		{name: "sign", value: "+18", fails: true},
		{name: "negative", value: "-1", fails: true},
		{name: "hex", value: "0x12", fails: true},
		{name: "empty", value: "", fails: true},
		{name: "overflow", value: "99999999999999999999999", fails: true},
	}

	for _, testCase := range testCases {
		got, err := parseWorkFactor(testCase.value, MaxWorkFactor)
		if testCase.fails {
			if !errors.Is(err, ErrHeader) {
				t.Errorf("%s: err = %v, want a header error", testCase.name, err)
			}
			continue
		}
		if err != nil || got != testCase.want {
			t.Errorf("%s: got %d, %v, want %d", testCase.name, got, err, testCase.want)
		}
	}
}

func TestWriterRefusesUseAfterClose(t *testing.T) {
	t.Parallel()

	writer, err := NewScryptWriter(io.Discard, testPassphrase, testWorkFactor)
	if err != nil {
		t.Fatalf("new scrypt writer: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	if _, err := writer.Write([]byte("x")); err == nil {
		t.Errorf("write after close: err = nil")
	}
	if err := writer.Close(); err == nil {
		t.Errorf("second close: err = nil")
	}
}

func TestNewScryptWriterRejects(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name       string
		dst        io.Writer
		passphrase []byte
		workFactor int
	}{
		{name: "no destination", passphrase: testPassphrase, workFactor: testWorkFactor},
		{name: "no passphrase", dst: io.Discard, workFactor: testWorkFactor},
		{name: "work factor zero", dst: io.Discard, passphrase: testPassphrase, workFactor: 0},
		{name: "work factor too high", dst: io.Discard, passphrase: testPassphrase, workFactor: 31},
	}

	for _, testCase := range testCases {
		if _, err := NewScryptWriter(testCase.dst, testCase.passphrase, testCase.workFactor); err == nil {
			t.Errorf("%s: err = nil", testCase.name)
		}
	}

	if _, err := NewScryptReader(nil, testPassphrase, MaxWorkFactor); err == nil {
		t.Errorf("new scrypt reader without a source: err = nil")
	}
	if _, err := NewScryptReader(bytes.NewReader(nil), nil, MaxWorkFactor); err == nil {
		t.Errorf("new scrypt reader without a passphrase: err = nil")
	}
	if _, err := NewScryptWriter(io.Discard, testPassphrase, 0); !errors.Is(err, altshiftErrors.ErrValidationError) {
		t.Errorf("work factor zero: err = %v, want a validation error", err)
	}
}
