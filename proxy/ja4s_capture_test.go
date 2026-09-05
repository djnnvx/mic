//go:build integration

package proxy

import (
	"bytes"
	"net"
	"sync"

	"github.com/djnnvx/mic/fingerprint"
)

// teeWriteConn tees every Write into a buffer and emits the JA4S once the
// buffer holds a complete ServerHello.
type teeWriteConn struct {
	net.Conn
	mu   sync.Mutex
	buf  bytes.Buffer
	ch   chan<- string
	sent bool
}

func (t *teeWriteConn) Write(p []byte) (int, error) {
	t.mu.Lock()
	if !t.sent {
		// In client-front MitM the proxy writes a plaintext "HTTP/1.1 200" line on
		// this conn first, so only collect from the first TLS handshake record.
		if t.buf.Len() > 0 || (len(p) >= 2 && p[0] == 0x16 && p[1] == 0x03) {
			t.buf.Write(p)
			if ja4s, err := captureToJA4S(t.buf.Bytes()); err == nil {
				select {
				case t.ch <- ja4s:
				default:
				}
				t.sent = true
			}
		}
	}
	t.mu.Unlock()
	return t.Conn.Write(p)
}

func captureToJA4S(raw []byte) (string, error) {
	sh, err := fingerprint.ParseServerHello(raw)
	if err != nil {
		return "", err
	}
	return fingerprint.ComputeJA4S(sh), nil
}

// captureJA4SListener wraps each accepted conn so the ServerHello mic writes
// back is captured and emitted on the returned channel.
func captureJA4SListener(ln net.Listener, p *Proxy, h Handler) <-chan string {
	ch := make(chan string, 16)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			wrapped := &teeWriteConn{Conn: conn, ch: ch}
			go h(wrapped, p)
		}
	}()
	return ch
}
