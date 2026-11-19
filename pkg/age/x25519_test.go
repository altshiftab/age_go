package age

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/altshiftab/age_go/pkg/bech32"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
)

// The identity of the specification's x25519 vector, and its recipient as
// age-keygen -y gives it.
const (
	vectorIdentity  = "AGE-SECRET-KEY-1EGTZVFFV20835NWYV6270LXYVK2VKNX2MMDKWYKLMGR48UAWX40Q2P2LM0"
	vectorRecipient = "age1xmwwc06ly3ee5rytxm9mflaz2u56jjj36s0mypdrwsvlul66mv4q47ryef"
)

func generateIdentity(t *testing.T) *X25519Identity {
	t.Helper()

	identity, err := GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate x25519 identity: %v", err)
	}

	return identity
}

func encryptX25519(t *testing.T, plaintext []byte, writeSize int, recipients ...*X25519Recipient) []byte {
	t.Helper()

	var encrypted bytes.Buffer
	writer, err := NewX25519Writer(&encrypted, recipients...)
	if err != nil {
		t.Fatalf("new x25519 writer: %v", err)
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

func decryptX25519(encrypted []byte, identities ...*X25519Identity) ([]byte, error) {
	reader, err := NewX25519Reader(bytes.NewReader(encrypted), identities...)
	if err != nil {
		return nil, err
	}

	return readReleased(reader)
}

func TestParseX25519Identity(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name          string
		input         string
		wantRecipient string
		wantErr       bool
	}{
		{name: "the specification's identity", input: vectorIdentity, wantRecipient: vectorRecipient},
		{name: "in lower case", input: strings.ToLower(vectorIdentity), wantRecipient: vectorRecipient},
		{name: "a recipient", input: vectorRecipient, wantErr: true},
		{name: "a hybrid identity", input: "AGE-SECRET-KEY-PQ-1HZLGZUPT4ETPKDEV8HSGFDCYZ4E522W0A7PU2LHT8EH9W6YLNC3SW78XKG", wantErr: true},
		{name: "a broken checksum", input: vectorIdentity[:len(vectorIdentity)-1] + "Q", wantErr: true},
		{name: "a short key", input: "AGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQSHKGEZ", wantErr: true},
		{name: "empty", input: "", wantErr: true},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			identity, err := ParseX25519Identity(testCase.input)
			if (err != nil) != testCase.wantErr {
				t.Fatalf("parse x25519 identity: %v, want error %t", err, testCase.wantErr)
			}
			if err != nil {
				return
			}

			if got := identity.Recipient().String(); got != testCase.wantRecipient {
				t.Errorf("recipient %q, want %q", got, testCase.wantRecipient)
			}
			if got := identity.String(); got != vectorIdentity {
				t.Errorf("identity written back as %q", got)
			}
		})
	}
}

func TestParseX25519Recipient(t *testing.T) {
	t.Parallel()

	// The same key under another human-readable part, checksum and all.
	_, key, err := bech32.Decode(vectorRecipient)
	if err != nil {
		t.Fatalf("bech32 decode: %v", err)
	}
	otherHrp, err := bech32.Encode("bge", key)
	if err != nil {
		t.Fatalf("bech32 encode: %v", err)
	}

	testCases := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{name: "the specification's recipient", input: vectorRecipient},
		{name: "in upper case", input: strings.ToUpper(vectorRecipient)},
		{name: "an identity", input: vectorIdentity, wantErr: true},
		{name: "a broken checksum", input: vectorRecipient[:len(vectorRecipient)-1] + "q", wantErr: true},
		{name: "another human-readable part", input: otherHrp, wantErr: true},
		{name: "empty", input: "", wantErr: true},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			recipient, err := ParseX25519Recipient(testCase.input)
			if (err != nil) != testCase.wantErr {
				t.Fatalf("parse x25519 recipient: %v, want error %t", err, testCase.wantErr)
			}
			if err == nil && recipient.String() != vectorRecipient {
				t.Errorf("written back as %q", recipient.String())
			}
			if err != nil && testCase.input != "" && !errors.Is(err, altshiftErrors.ErrParseError) {
				t.Errorf("parse x25519 recipient: %v, want a parse error", err)
			}
		})
	}
}

func TestX25519RoundTrip(t *testing.T) {
	t.Parallel()

	first := generateIdentity(t)
	second := generateIdentity(t)

	testCases := []struct {
		name       string
		size       int
		writeSize  int
		recipients []*X25519Recipient
		identities []*X25519Identity
	}{
		{name: "empty", size: 0, writeSize: 1, recipients: []*X25519Recipient{first.Recipient()}, identities: []*X25519Identity{first}},
		{name: "one chunk exactly", size: chunkSize, writeSize: 4096, recipients: []*X25519Recipient{first.Recipient()}, identities: []*X25519Identity{first}},
		{name: "several chunks, byte by byte", size: 2*chunkSize + 3, writeSize: 1, recipients: []*X25519Recipient{first.Recipient()}, identities: []*X25519Identity{first}},
		{name: "the second of two recipients", size: 1000, writeSize: 7, recipients: []*X25519Recipient{first.Recipient(), second.Recipient()}, identities: []*X25519Identity{second}},
		{name: "the right one of two identities", size: 1000, writeSize: 1000, recipients: []*X25519Recipient{second.Recipient()}, identities: []*X25519Identity{first, second}},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			plaintext := randomPlaintext(t, testCase.size)
			encrypted := encryptX25519(t, plaintext, testCase.writeSize, testCase.recipients...)

			decrypted, err := decryptX25519(encrypted, testCase.identities...)
			if err != nil {
				t.Fatalf("decrypt: %v", err)
			}
			if !bytes.Equal(decrypted, plaintext) {
				t.Errorf("decrypted %d bytes that differ from the %d encrypted", len(decrypted), len(plaintext))
			}
		})
	}
}

func TestX25519Refuses(t *testing.T) {
	t.Parallel()

	identity := generateIdentity(t)
	stranger := generateIdentity(t)
	encrypted := encryptX25519(t, []byte("the backup"), 64, identity.Recipient())
	scryptEncrypted := encrypt(t, []byte("the backup"), 64)

	testCases := []struct {
		name      string
		encrypted []byte
		identity  *X25519Identity
		wantErr   error
	}{
		{name: "an identity it was not encrypted to", encrypted: encrypted, identity: stranger, wantErr: ErrNoMatch},
		{name: "a passphrase-encrypted file", encrypted: scryptEncrypted, identity: identity, wantErr: ErrNoMatch},
		{name: "a truncated header", encrypted: encrypted[:20], identity: identity, wantErr: ErrHeader},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			_, err := decryptX25519(testCase.encrypted, testCase.identity)
			if !errors.Is(err, testCase.wantErr) {
				t.Errorf("decrypt: %v, want %v", err, testCase.wantErr)
			}
		})
	}
}

func TestX25519RejectsArguments(t *testing.T) {
	t.Parallel()

	identity := generateIdentity(t)

	if _, err := NewX25519Writer(&bytes.Buffer{}); err == nil {
		t.Error("new x25519 writer with no recipients: no error")
	}
	if _, err := NewX25519Writer(nil, identity.Recipient()); err == nil {
		t.Error("new x25519 writer with no destination: no error")
	}
	if _, err := NewX25519Writer(&bytes.Buffer{}, &X25519Recipient{}); err == nil {
		t.Error("new x25519 writer with an empty recipient: no error")
	}
	if _, err := NewX25519Reader(bytes.NewReader(nil)); err == nil {
		t.Error("new x25519 reader with no identities: no error")
	}
	if _, err := NewX25519Reader(bytes.NewReader(nil), &X25519Identity{}); err == nil {
		t.Error("new x25519 reader with an empty identity: no error")
	}
}

func runCommand(t *testing.T, name string, arguments ...string) []byte {
	t.Helper()

	output, err := exec.CommandContext(t.Context(), name, arguments...).Output() //nolint:gosec // The arguments are the test's own.
	if err != nil {
		t.Fatalf("%s %s: %v", name, strings.Join(arguments, " "), err)
	}

	return output
}

// TestX25519AgeCommand checks interoperability with the reference
// implementation in both directions, as TestAgeCommand does for passphrases:
// what this package encrypts to a recipient, age decrypts with the identity,
// and the other way round, with keys made by either side.
func TestX25519AgeCommand(t *testing.T) {
	t.Parallel()

	for _, name := range []string{"age", "age-keygen"} {
		if _, err := exec.LookPath(name); err != nil {
			t.Skipf("%s is not installed", name)
		}
	}

	directory := t.TempDir()
	plaintext := randomPlaintext(t, 2*chunkSize+777)

	t.Run("this package to age", func(t *testing.T) {
		t.Parallel()

		identity := generateIdentity(t)
		identityPath := filepath.Join(directory, "ours.identity")
		encryptedPath := filepath.Join(directory, "ours.age")
		if err := os.WriteFile(identityPath, []byte(identity.String()+"\n"), 0o600); err != nil {
			t.Fatalf("os write file (identity): %v", err)
		}
		if err := os.WriteFile(encryptedPath, encryptX25519(t, plaintext, 1000, identity.Recipient()), 0o600); err != nil {
			t.Fatalf("os write file: %v", err)
		}

		if got := strings.TrimSpace(string(runCommand(t, "age-keygen", "-y", identityPath))); got != identity.Recipient().String() {
			t.Errorf("age-keygen -y gives %q, this package %q", got, identity.Recipient().String())
		}

		decrypted := runCommand(t, "age", "--decrypt", "--identity", identityPath, encryptedPath)
		if !bytes.Equal(decrypted, plaintext) {
			t.Errorf("age decrypted %d bytes that differ from the %d encrypted", len(decrypted), len(plaintext))
		}
	})

	t.Run("age to this package", func(t *testing.T) {
		t.Parallel()

		identityPath := filepath.Join(directory, "theirs.identity")
		plaintextPath := filepath.Join(directory, "theirs.plaintext")
		runCommand(t, "age-keygen", "-o", identityPath)
		if err := os.WriteFile(plaintextPath, plaintext, 0o600); err != nil {
			t.Fatalf("os write file: %v", err)
		}

		recipient := strings.TrimSpace(string(runCommand(t, "age-keygen", "-y", identityPath)))
		encrypted := runCommand(t, "age", "--encrypt", "--recipient", recipient, plaintextPath)

		keyFile, err := os.ReadFile(identityPath) //nolint:gosec // The test's own file.
		if err != nil {
			t.Fatalf("os read file: %v", err)
		}
		var identity *X25519Identity
		for line := range strings.SplitSeq(string(keyFile), "\n") {
			if strings.HasPrefix(line, "AGE-SECRET-KEY-1") {
				if identity, err = ParseX25519Identity(line); err != nil {
					t.Fatalf("parse x25519 identity: %v", err)
				}
			}
		}
		if identity == nil {
			t.Fatal("age-keygen wrote no identity")
		}

		decrypted, err := decryptX25519(encrypted, identity)
		if err != nil {
			t.Fatalf("decrypt: %v", err)
		}
		if !bytes.Equal(decrypted, plaintext) {
			t.Errorf("decrypted %d bytes that differ from the %d age encrypted", len(decrypted), len(plaintext))
		}
	})
}
