// Package tokenkeep keeps a CLI's login token in the OS keyring: the macOS
// Keychain through `security`, or the Linux Secret Service through
// `secret-tool`. It has no dependencies and stores one secret per account.
//
// On macOS an item written by `security` can be read by any process running
// as the same user. That is the platform's rule for the tool, not something
// this package can tighten.
package tokenkeep

import (
	"bytes"
	"errors"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
)

// Backends, as returned by Backend and stored by callers beside the account.
const (
	MacOSKeychain = "macos-keychain"
	SecretService = "secret-service"
)

// ErrNotFound is a lookup that found no item: logged out, not broken.
var ErrNotFound = errors.New("not found")

// macItemNotFound is security's exit status for "The specified item could
// not be found in the keychain".
const macItemNotFound = 44

// Backend names the OS keyring available on this machine, or "" for none.
func Backend() string {
	switch runtime.GOOS {
	case "darwin":
		if _, err := exec.LookPath("security"); err == nil {
			return MacOSKeychain
		}
	case "linux":
		if _, err := exec.LookPath("secret-tool"); err == nil {
			return SecretService
		}
	}
	return ""
}

// Keyring stores tokens under one service name, usually the CLI's name.
type Keyring struct {
	Service string
}

// macQuote quotes one argument for `security -i`, which reads command
// lines from stdin and accepts double quotes with backslash escapes.
func macQuote(s string) (string, error) {
	if strings.ContainsAny(s, "\r\n\x00") {
		return "", errors.New("value contains a line break")
	}
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`, nil
}

// Write stores token for account in backend, replacing any earlier one.
func (k Keyring) Write(backend, account, token string) error {
	switch backend {
	case MacOSKeychain:
		// The token reaches `security -i` on stdin, never argv, so it does
		// not show in ps. security -i exits 0 even when its command fails,
		// so read the item back to confirm it landed.
		var q [3]string
		for i, v := range []string{account, k.Service, token} {
			s, err := macQuote(v)
			if err != nil {
				return err
			}
			q[i] = s
		}
		cmd := exec.Command("security", "-i")
		cmd.Stdin = strings.NewReader("add-generic-password -U -a " + q[0] + " -s " + q[1] + " -w " + q[2] + "\n")
		if err := cmd.Run(); err != nil {
			return err
		}
		if got, err := k.Read(backend, account); err != nil || got != token {
			return errors.New("macOS Keychain did not store the token")
		}
		return nil
	case SecretService:
		cmd := exec.Command("secret-tool", "store", "--label", k.Service+" token for "+account, "service", k.Service, "account", account)
		cmd.Stdin = strings.NewReader(token)
		return cmd.Run()
	}
	return errors.New("no keyring")
}

// Read returns ErrNotFound for a missing item and any other failure
// (locked keychain, denied access) as a real error.
func (k Keyring) Read(backend, account string) (string, error) {
	var cmd *exec.Cmd
	switch backend {
	case MacOSKeychain:
		cmd = exec.Command("security", "find-generic-password", "-a", account, "-s", k.Service, "-w")
	case SecretService:
		cmd = exec.Command("secret-tool", "lookup", "service", k.Service, "account", account)
	default:
		return "", errors.New("unknown credential storage " + backend)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return "", keyringErr(backend, "read", err, stderr.String())
	}
	tok := string(bytes.TrimSpace(out))
	if tok == "" {
		return "", ErrNotFound
	}
	return tok, nil
}

// Delete removes account's item. A missing item is not an error.
func (k Keyring) Delete(backend, account string) error {
	var cmd *exec.Cmd
	switch backend {
	case MacOSKeychain:
		cmd = exec.Command("security", "delete-generic-password", "-a", account, "-s", k.Service)
	case SecretService:
		cmd = exec.Command("secret-tool", "clear", "service", k.Service, "account", account)
	default:
		return errors.New("unknown credential storage " + backend)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if err := keyringErr(backend, "delete", err, stderr.String()); !errors.Is(err, ErrNotFound) {
			return err
		}
	}
	return nil
}

// keyringErr maps a keyring command failure to ErrNotFound when the tool
// said the item is missing, otherwise to a descriptive error.
func keyringErr(backend, op string, err error, stderr string) error {
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		if backend == MacOSKeychain && ee.ExitCode() == macItemNotFound {
			return ErrNotFound
		}
		// secret-tool exits 1 with nothing on stderr when nothing matched.
		if backend == SecretService && ee.ExitCode() == 1 && strings.TrimSpace(stderr) == "" {
			return ErrNotFound
		}
	}
	msg := strings.TrimSpace(stderr)
	if msg == "" {
		msg = err.Error()
	}
	return fmt.Errorf("%s: %s token: %s", backend, op, msg)
}
