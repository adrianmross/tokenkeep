package tokenkeep

import (
	"errors"
	"os"
	"testing"
)

func TestMacQuote(t *testing.T) {
	for in, want := range map[string]string{
		`plain`:      `"plain"`,
		`a "b" c`:    `"a \"b\" c"`,
		`back\slash`: `"back\\slash"`,
	} {
		if got, err := macQuote(in); err != nil || got != want {
			t.Errorf("macQuote(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	// A line break would start a second `security -i` command.
	for _, in := range []string{"a\nb", "a\rb", "a\x00b"} {
		if _, err := macQuote(in); err == nil {
			t.Errorf("macQuote(%q) accepted a line break", in)
		}
	}
}

func TestUnknownBackend(t *testing.T) {
	k := Keyring{Service: "tokenkeep-test"}
	if _, err := k.Read("nope", "a"); err == nil || errors.Is(err, ErrNotFound) {
		t.Errorf("Read on an unknown backend = %v; want a real error, not ErrNotFound", err)
	}
	if err := k.Delete("nope", "a"); err == nil {
		t.Error("Delete on an unknown backend succeeded")
	}
	if err := k.Write("", "a", "t"); err == nil {
		t.Error("Write with no backend succeeded")
	}
}

// TestRoundTrip uses the real keyring, so it only runs when asked:
// TOKENKEEP_LIVE=1 go test ./...
func TestRoundTrip(t *testing.T) {
	backend := Backend()
	if os.Getenv("TOKENKEEP_LIVE") == "" || backend == "" {
		t.Skip("set TOKENKEEP_LIVE=1 on a machine with a keyring")
	}
	k := Keyring{Service: "tokenkeep-test"}
	account := `http://127.0.0.1:1 "quoted"`
	t.Cleanup(func() { _ = k.Delete(backend, account) })
	if _, err := k.Read(backend, account); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Read before Write = %v; want ErrNotFound", err)
	}
	for _, tok := range []string{`first`, `sec"ond\ with spaces`} { // second Write replaces the first
		if err := k.Write(backend, account, tok); err != nil {
			t.Fatal(err)
		}
		if got, err := k.Read(backend, account); err != nil || got != tok {
			t.Fatalf("Read = %q, %v; want %q", got, err, tok)
		}
	}
	if err := k.Delete(backend, account); err != nil {
		t.Fatal(err)
	}
	if err := k.Delete(backend, account); err != nil {
		t.Fatalf("second Delete = %v; a missing item is not an error", err)
	}
	if _, err := k.Read(backend, account); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Read after Delete = %v; want ErrNotFound", err)
	}
}
