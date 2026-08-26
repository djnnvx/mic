package proxy

import (
	"net"
	"testing"
	"time"
)

func TestParseAuthority(t *testing.T) {
	cases := []struct {
		name         string
		in           string
		wantServer   string
		wantHostPort string
	}{
		{"hostname with explicit port", "example.com:443", "example.com", "example.com:443"},
		{"hostname with non-443 port", "localhost:3000", "localhost", "localhost:3000"},
		{"hostname with high port", "api.internal:8443", "api.internal", "api.internal:8443"},
		{"bare hostname defaults to 443", "example.com", "example.com", "example.com:443"},
		{"bare localhost defaults to 443", "localhost", "localhost", "localhost:443"},

		{"subdomain with port", "www.example.com:443", "www.example.com", "www.example.com:443"},
		{"subdomain with non-443 port", "api.example.com:8080", "api.example.com", "api.example.com:8080"},
		{"deep subdomain with port", "a.b.c.example.com:9000", "a.b.c.example.com", "a.b.c.example.com:9000"},
		{"bare subdomain defaults to 443", "www.example.com", "www.example.com", "www.example.com:443"},
		{"bare deep subdomain defaults to 443", "a.b.c.example.com", "a.b.c.example.com", "a.b.c.example.com:443"},
		{"hyphenated hostname with port", "my-host-1.example.com:8443", "my-host-1.example.com", "my-host-1.example.com:8443"},

		{"IPv4 with explicit port", "127.0.0.1:8080", "127.0.0.1", "127.0.0.1:8080"},
		{"IPv4 with 443", "10.0.0.1:443", "10.0.0.1", "10.0.0.1:443"},
		{"bare IPv4 defaults to 443", "10.0.0.1", "10.0.0.1", "10.0.0.1:443"},

		{"IPv6 bracketed with port", "[::1]:443", "::1", "[::1]:443"},
		{"IPv6 bracketed with non-443 port", "[fe80::1]:8080", "fe80::1", "[fe80::1]:8080"},
		{"IPv6 bracketed without port", "[::1]", "::1", "[::1]:443"},
		{"IPv6 full address bracketed with port", "[2001:db8::1]:9000", "2001:db8::1", "[2001:db8::1]:9000"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotServer, gotHostPort := parseAuthority(tc.in)
			if gotServer != tc.wantServer {
				t.Errorf("server: got %q, want %q", gotServer, tc.wantServer)
			}
			if gotHostPort != tc.wantHostPort {
				t.Errorf("hostPort: got %q, want %q", gotHostPort, tc.wantHostPort)
			}
		})
	}
}

func TestHttpsHandler_SilentPeerTimesOut(t *testing.T) {
	orig := headerReadTimeout
	headerReadTimeout = 200 * time.Millisecond
	defer func() { headerReadTimeout = orig }()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	defer ln.Close()

	done := make(chan struct{})
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		HttpsHandler(conn, &Proxy{})
		close(done)
	}()

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("net.Dial: %v", err)
	}
	defer client.Close()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("HttpsHandler did not return on a peer that sent nothing")
	}
}
