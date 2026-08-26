package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// run executes the client command with args, using an unroutable listen port so
// that anything reaching p.Run() fails there instead of binding a real socket.
func runClient(t *testing.T, args ...string) error {
	t.Helper()
	c := newClientCmd()
	c.SetOut(os.NewFile(0, os.DevNull))
	c.SetErr(os.NewFile(0, os.DevNull))
	c.SetArgs(append([]string{"--listen", "127.0.0.1:99999"}, args...))
	return c.Execute()
}

func TestGarbageCAFileIsRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, []byte("this is not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := runClient(t, "--ca", path)
	if err == nil || !strings.Contains(err.Error(), "no certificates found") {
		t.Errorf("garbage CA accepted; got err=%v, want one naming the bad file", err)
	}
}

func TestHalfSpecifiedInterceptPairIsRefused(t *testing.T) {
	dir := t.TempDir()
	for _, flag := range []string{"--intercept-cert", "--intercept-key"} {
		err := runClient(t, flag, filepath.Join(dir, "x.pem"))
		if err == nil || !strings.Contains(err.Error(), "must be given together") {
			t.Errorf("%s alone accepted; got err=%v", flag, err)
		}
		if _, statErr := os.Stat(filepath.Join(dir, "x.pem")); statErr == nil {
			t.Errorf("%s alone wrote a CA file it should have refused to create", flag)
		}
	}
}

func TestProxyURL(t *testing.T) {
	for in, want := range map[string]string{
		":8080":          "localhost:8080",
		"127.0.0.1:8080": "127.0.0.1:8080",
	} {
		if got := proxyURL(in); got != want {
			t.Errorf("proxyURL(%q) = %q; want %q", in, got, want)
		}
	}
}
