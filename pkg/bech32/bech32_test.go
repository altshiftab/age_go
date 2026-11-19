package bech32

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
)

// TestDecodeGroups runs BIP 173's checksum vectors. They are about the string's
// structure and checksum rather than about whole bytes, which some of the valid
// ones do not regroup into, so they go through decodeGroups.
func TestDecodeGroups(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name    string
		input   string
		wantHrp string
		wantErr bool
	}{
		{name: "upper case", input: "A12UEL5L", wantHrp: "a"},
		{name: "lower case", input: "a12uel5l", wantHrp: "a"},
		{
			name:    "a long human-readable part holding the separator and excluded characters",
			input:   "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs",
			wantHrp: "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio",
		},
		{name: "the whole charset", input: "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw", wantHrp: "abcdef"},
		{
			name:    "a separator for a human-readable part",
			input:   "11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j",
			wantHrp: "1",
		},
		{name: "words", input: "split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w", wantHrp: "split"},
		{name: "a punctuation human-readable part", input: "?1ezyfcl", wantHrp: "?"},
		{name: "a space in the human-readable part", input: "\x201nwldj5", wantErr: true},
		{name: "a delete in the human-readable part", input: "\x7f1axkwrx", wantErr: true},
		{name: "a non-ascii human-readable part", input: "\x801eym55h", wantErr: true},
		{name: "no separator", input: "pzry9x0s0muk", wantErr: true},
		{name: "an empty human-readable part", input: "1pzry9x0s0muk", wantErr: true},
		{name: "a character outside the charset", input: "x1b4n0q5v", wantErr: true},
		{name: "a short checksum", input: "li1dgmt3", wantErr: true},
		{name: "a non-ascii checksum character", input: "de1lg7wt\xff", wantErr: true},
		{name: "a checksum over the upper-case form", input: "A1G7SGD8", wantErr: true},
		{name: "an empty human-readable part before data", input: "10a06t8", wantErr: true},
		{name: "an empty human-readable part before a checksum", input: "1qzzfhee", wantErr: true},
		{name: "mixed case", input: "A12uEL5L", wantErr: true},
		{name: "empty", input: "", wantErr: true},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			hrp, _, err := decodeGroups(testCase.input)
			if (err != nil) != testCase.wantErr {
				t.Fatalf("decode groups: %v, want error %t", err, testCase.wantErr)
			}
			if hrp != testCase.wantHrp {
				t.Errorf("hrp %q, want %q", hrp, testCase.wantHrp)
			}
		})
	}
}

// groupsString writes 5-bit groups as a Bech32 string with a valid checksum,
// whether or not they regroup into whole bytes.
func groupsString(hrp string, groups []byte) string {
	var builder strings.Builder
	builder.WriteString(hrp)
	builder.WriteByte(separator)
	for _, group := range append(append([]byte{}, groups...), createChecksum(hrp, groups)...) {
		builder.WriteByte(charset[group])
	}

	return builder.String()
}

func TestDecodeRefusesParseErrors(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name  string
		input string
	}{
		{name: "a checksum mismatch", input: "age1qqqqqqqq"},
		{name: "mixed case", input: "Age1EGTZVFFV20835NWYV6270LXYVK2VKNX2MMDKWYKLMGR48UAWX40Q2P2LM0"},
		// Ten bits: a byte, and two padding bits that are not zero.
		{name: "non-zero padding", input: groupsString("a", []byte{0, 1})},
		// Five bits: padding a whole group long, holding no byte.
		{name: "a whole group of padding", input: groupsString("a", []byte{0})},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			_, _, err := Decode(testCase.input)
			if !errors.Is(err, altshiftErrors.ErrParseError) {
				t.Errorf("decode: %v, want a parse error", err)
			}
		})
	}
}

func TestRoundTrip(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string
		hrp  string
		data []byte
		want string
	}{
		{name: "empty data", hrp: "a", data: []byte{}, want: "a12uel5l"},
		{name: "one byte", hrp: "test", data: []byte{0xff}},
		{name: "a key's length", hrp: "age", data: bytes.Repeat([]byte{0xa5}, 32)},
		{name: "an upper-case human-readable part is written in lower case", hrp: "AGE-SECRET-KEY-", data: bytes.Repeat([]byte{1}, 32)},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			encoded, err := Encode(testCase.hrp, testCase.data)
			if err != nil {
				t.Fatalf("encode: %v", err)
			}
			if testCase.want != "" && encoded != testCase.want {
				t.Errorf("encoded %q, want %q", encoded, testCase.want)
			}
			if encoded != strings.ToLower(encoded) {
				t.Errorf("encoded %q is not lower case", encoded)
			}

			// Decoding gives the human-readable part in lower case exactly,
			// whichever case it was encoded or written in.
			wantHrp := strings.ToLower(testCase.hrp)
			for _, form := range []string{encoded, strings.ToUpper(encoded)} {
				hrp, data, err := Decode(form)
				if err != nil {
					t.Fatalf("decode %q: %v", form, err)
				}
				if hrp != wantHrp {
					t.Errorf("decoded hrp %q, want %q", hrp, wantHrp)
				}
				if !bytes.Equal(data, testCase.data) {
					t.Errorf("decoded %x, want %x", data, testCase.data)
				}
			}
		})
	}
}

// TestAgeKey decodes a secret key from the age specification's test vectors
// and writes it back the same way.
func TestAgeKey(t *testing.T) {
	t.Parallel()

	const key = "AGE-SECRET-KEY-1EGTZVFFV20835NWYV6270LXYVK2VKNX2MMDKWYKLMGR48UAWX40Q2P2LM0"

	hrp, data, err := Decode(key)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if hrp != "age-secret-key-" {
		t.Errorf("hrp %q", hrp)
	}
	if len(data) != 32 {
		t.Fatalf("decoded %d bytes, want 32", len(data))
	}

	encoded, err := Encode(hrp, data)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	upper := strings.ToUpper(encoded)
	if upper != key {
		t.Errorf("encoded %q, want %q", upper, key)
	}
}

func TestEncodeRejects(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name string
		hrp  string
	}{
		{name: "an empty human-readable part", hrp: ""},
		{name: "a space", hrp: "a b"},
		{name: "a non-ascii character", hrp: "å"},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			if _, err := Encode(testCase.hrp, []byte{1}); err == nil {
				t.Errorf("encode %q: no error", testCase.hrp)
			}
		})
	}
}
