// Package bech32 encodes and decodes Bech32 strings (BIP 173), the encoding age
// writes its keys in.
//
// It is BIP 173's original Bech32, not Bech32m, and like age's own it sets no
// limit on a string's length: BIP 173's 90 characters were chosen for Bitcoin
// addresses and say nothing about keys.
package bech32

import (
	"fmt"
	"strings"

	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/altshiftab/utils_go/pkg/errors/types/empty_error"
)

const (
	charset   = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
	separator = '1'
	// checksumLength is the number of characters the checksum takes.
	checksumLength = 6
)

var generator = [5]uint32{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}

// charsetIndex maps a character to its value, or -1 for one outside the
// charset.
var charsetIndex = func() [128]int8 {
	var index [128]int8
	for i := range index {
		index[i] = -1
	}
	for i := range len(charset) {
		index[charset[i]] = int8(i)
	}
	return index
}()

func parseError(detail string) error {
	return altshiftErrors.NewWithTrace(fmt.Errorf("%w: bech32: %s", altshiftErrors.ErrParseError, detail))
}

func polymod(values []byte) uint32 {
	checksum := uint32(1)
	for _, value := range values {
		top := checksum >> 25
		checksum = (checksum&0x1ffffff)<<5 ^ uint32(value)
		for i, g := range generator {
			if (top>>i)&1 == 1 {
				checksum ^= g
			}
		}
	}

	return checksum
}

// expandHrp is the human-readable part as the checksum covers it: each
// character's high bits, a zero, then each character's low bits.
func expandHrp(hrp string) []byte {
	expanded := make([]byte, 0, 2*len(hrp)+1)
	for i := range len(hrp) {
		expanded = append(expanded, hrp[i]>>5)
	}
	expanded = append(expanded, 0)
	for i := range len(hrp) {
		expanded = append(expanded, hrp[i]&31)
	}

	return expanded
}

func createChecksum(hrp string, data []byte) []byte {
	values := append(expandHrp(hrp), data...)
	values = append(values, make([]byte, checksumLength)...)
	mod := polymod(values) ^ 1

	checksum := make([]byte, checksumLength)
	for i := range checksum {
		checksum[i] = byte((mod >> (5 * (5 - i))) & 31)
	}

	return checksum
}

// convertBits regroups data from fromBits-bit to toBits-bit groups. Encoding
// pads the last group with zeros; decoding refuses any padding that is a whole
// group or not zero, so that every value has exactly one encoding.
func convertBits(data []byte, fromBits uint, toBits uint, pad bool) ([]byte, error) {
	var (
		accumulator uint32
		bits        uint
		converted   []byte
	)
	maxValue := uint32(1)<<toBits - 1

	for _, value := range data {
		if uint32(value)>>fromBits != 0 {
			return nil, parseError(fmt.Sprintf("a value does not fit in %d bits", fromBits))
		}
		accumulator = accumulator<<fromBits | uint32(value)
		bits += fromBits
		for bits >= toBits {
			bits -= toBits
			converted = append(converted, byte((accumulator>>bits)&maxValue)) //nolint:gosec // Masked to toBits, at most 8, bits.
		}
	}

	if pad {
		if bits > 0 {
			converted = append(converted, byte((accumulator<<(toBits-bits))&maxValue)) //nolint:gosec // Masked to toBits, at most 8, bits.
		}
	} else if bits >= fromBits {
		return nil, parseError("the padding is a whole group or more")
	} else if (accumulator<<(toBits-bits))&maxValue != 0 {
		return nil, parseError("the padding is not zero")
	}

	return converted, nil
}

func validHrp(hrp string) bool {
	if hrp == "" {
		return false
	}
	for i := range len(hrp) {
		if hrp[i] < 33 || hrp[i] > 126 {
			return false
		}
	}

	return true
}

// Encode encodes data under the human-readable part hrp, in lower case.
// Callers that want upper case, as age's secret keys are written, convert the
// result: Bech32 is case-insensitive as long as a string is all one case.
func Encode(hrp string, data []byte) (string, error) {
	if hrp == "" {
		return "", altshiftErrors.NewWithTrace(empty_error.New("hrp"))
	}
	if !validHrp(hrp) {
		return "", altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: bech32: the human-readable part %q has a character outside 33-126", altshiftErrors.ErrValidationError, hrp),
		)
	}
	hrp = strings.ToLower(hrp)

	groups, err := convertBits(data, 8, 5, true)
	if err != nil {
		return "", fmt.Errorf("convert bits: %w", err)
	}

	var builder strings.Builder
	builder.Grow(len(hrp) + 1 + len(groups) + checksumLength)
	builder.WriteString(hrp)
	builder.WriteByte(separator)
	for _, group := range append(groups, createChecksum(hrp, groups)...) {
		builder.WriteByte(charset[group])
	}

	return builder.String(), nil
}

// Decode decodes s, returning its human-readable part in lower case and its
// data. A string mixing upper and lower case, with a character outside the
// charset, with a checksum that does not match, or whose data does not regroup
// into whole bytes is refused as a parse error.
func Decode(s string) (string, []byte, error) {
	hrp, groups, err := decodeGroups(s)
	if err != nil {
		return "", nil, fmt.Errorf("decode groups: %w", err)
	}

	data, err := convertBits(groups, 5, 8, false)
	if err != nil {
		return "", nil, fmt.Errorf("convert bits: %w", err)
	}

	return hrp, data, nil
}

// decodeGroups checks s as a Bech32 string and returns its human-readable
// part, in lower case, and its data as 5-bit groups, without the checksum.
func decodeGroups(s string) (string, []byte, error) {
	if s == "" {
		return "", nil, altshiftErrors.NewWithTrace(empty_error.New("bech32 string"))
	}
	// Checked before any case is folded: Unicode folding maps some characters outside ASCII onto
	// ASCII letters (U+212A, the Kelvin sign, onto k), which would let them through.
	for i := range len(s) {
		if s[i] < 33 || s[i] > 126 {
			return "", nil, parseError("a character is outside 33-126")
		}
	}
	lower := strings.ToLower(s)
	if lower != s && strings.ToUpper(s) != s {
		return "", nil, parseError("the string mixes upper and lower case")
	}

	separatorIndex := strings.LastIndexByte(lower, separator)
	if separatorIndex < 1 {
		return "", nil, parseError("there is no human-readable part before the separator")
	}
	if len(lower)-separatorIndex-1 < checksumLength {
		return "", nil, parseError("the data part is shorter than the checksum")
	}

	hrp := lower[:separatorIndex]
	if !validHrp(hrp) {
		return "", nil, parseError("the human-readable part has a character outside 33-126")
	}

	encoded := lower[separatorIndex+1:]
	values := make([]byte, len(encoded))
	for i := range len(encoded) {
		c := encoded[i]
		if c >= 128 || charsetIndex[c] < 0 {
			return "", nil, parseError(fmt.Sprintf("%q is not in the charset", c))
		}
		values[i] = byte(charsetIndex[c])
	}

	if polymod(append(expandHrp(hrp), values...)) != 1 {
		return "", nil, parseError("the checksum does not match")
	}

	return hrp, values[:len(values)-checksumLength], nil
}
