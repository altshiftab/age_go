package age

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// runAge runs the age command in a pseudo-terminal, which is the only place it
// takes a passphrase from, with input typed into it.
func runAge(t *testing.T, input string, arguments ...string) {
	t.Helper()

	quoted := make([]string, len(arguments))
	for i, argument := range arguments {
		quoted[i] = "'" + strings.ReplaceAll(argument, "'", `'\''`) + "'"
	}

	command := exec.CommandContext(t.Context(), "script", "-qec", "age "+strings.Join(quoted, " "), "/dev/null") //nolint:gosec // The arguments are the test's own.
	command.Stdin = strings.NewReader(input)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("age %s: %v\n%s", strings.Join(arguments, " "), err, output)
	}
}

func requireAgeCommand(t *testing.T) {
	t.Helper()

	for _, name := range []string{"age", "script"} {
		if _, err := exec.LookPath(name); err != nil {
			t.Skipf("%s is not installed", name)
		}
	}
}

// TestAgeCommand checks interoperability with the reference implementation in
// both directions: what this package encrypts the age command decrypts, and
// the other way round.
func TestAgeCommand(t *testing.T) {
	t.Parallel()
	requireAgeCommand(t)

	directory := t.TempDir()
	plaintext := randomPlaintext(t, 2*chunkSize+777)
	passphrase := string(testPassphrase)

	t.Run("this package to age", func(t *testing.T) {
		t.Parallel()

		encryptedPath := filepath.Join(directory, "ours.age")
		decryptedPath := filepath.Join(directory, "ours.decrypted")
		if err := os.WriteFile(encryptedPath, encrypt(t, plaintext, 1000), 0o600); err != nil {
			t.Fatalf("os write file: %v", err)
		}

		runAge(t, passphrase+"\n", "--decrypt", "--output", decryptedPath, encryptedPath)

		decrypted, err := os.ReadFile(decryptedPath) //nolint:gosec // The test's own file.
		if err != nil {
			t.Fatalf("os read file: %v", err)
		}
		if !bytes.Equal(decrypted, plaintext) {
			t.Errorf("age decrypted %d bytes that differ from the %d encrypted", len(decrypted), len(plaintext))
		}
	})

	t.Run("age to this package", func(t *testing.T) {
		t.Parallel()

		plaintextPath := filepath.Join(directory, "theirs.plaintext")
		encryptedPath := filepath.Join(directory, "theirs.age")
		if err := os.WriteFile(plaintextPath, plaintext, 0o600); err != nil {
			t.Fatalf("os write file: %v", err)
		}

		// The passphrase twice: asked for, then confirmed.
		runAge(t, passphrase+"\n"+passphrase+"\n", "--passphrase", "--output", encryptedPath, plaintextPath)

		encrypted, err := os.ReadFile(encryptedPath) //nolint:gosec // The test's own file.
		if err != nil {
			t.Fatalf("os read file: %v", err)
		}
		decrypted, err := decrypt(encrypted, testPassphrase, MaxWorkFactor)
		if err != nil {
			t.Fatalf("decrypt: %v", err)
		}
		if !bytes.Equal(decrypted, plaintext) {
			t.Errorf("decrypted %d bytes that differ from the %d age encrypted", len(decrypted), len(plaintext))
		}
	})
}
