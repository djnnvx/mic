package proxy

import (
	"bufio"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	utls "github.com/bogdanfinn/utls"
	"github.com/djnnvx/mic/fingerprint"
)

const (
	dialTimeout         = 10 * time.Second
	acceptRetryDelay    = 5 * time.Millisecond
	acceptMaxRetryDelay = 1 * time.Second
)

type Proxy struct {
	ListenAddr  string
	BackendAddr string // server-front: backend host:port
	CAPool      *x509.CertPool
	Fingerprint *fingerprint.TLSFingerprint
	LocalCA     *LocalCA // client-front: MitM CA for TLS interception
	Handler     Handler
}

type Handler func(conn net.Conn, p *Proxy)

// dialTarget dials host (host:port) and returns a uTLS connection after a
// successful handshake. Falls back to HelloRandomized when no fingerprint is set.
func (p *Proxy) dialTarget(host string) (*utls.UConn, error) {
	tcpConn, err := net.DialTimeout("tcp", host, dialTimeout)
	if err != nil {
		return nil, err
	}

	helloID := utls.HelloRandomized
	if p.Fingerprint != nil {
		helloID = p.Fingerprint.ClientHelloID()
	}

	serverName, _, err := net.SplitHostPort(host)
	if err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("dialTarget: parse host %q: %w", host, err)
	}

	cfg := &utls.Config{ServerName: serverName}
	if p.CAPool != nil {
		cfg.RootCAs = p.CAPool
	}

	uconn := utls.UClient(tcpConn, cfg, helloID, false, false, false)
	if err := uconn.Handshake(); err != nil {
		uconn.Close()
		return nil, err
	}
	return uconn, nil
}

// bufferedConn pairs a net.Conn with a bufio.Reader that may already contain
// data read ahead from the underlying conn (e.g. after http.ReadRequest).
// Reads come from the buffer; writes and Close go to the conn.
type bufferedConn struct {
	r *bufio.Reader
	net.Conn
}

func (b *bufferedConn) Read(p []byte) (int, error) { return b.r.Read(p) }

func (b *bufferedConn) CloseWrite() error {
	if hc, ok := b.Conn.(halfCloser); ok {
		return hc.CloseWrite()
	}
	return errNoHalfClose
}

var errNoHalfClose = errors.New("proxy: connection does not support half-close")

// halfCloser is implemented by *net.TCPConn, *tls.Conn and *utls.UConn.
type halfCloser interface {
	CloseWrite() error
}

// closeWrite shuts down only the write side so the peer still sees the data
// already sent. Falls back to a full Close when half-close is unavailable.
func closeWrite(c io.Closer) {
	if hc, ok := c.(halfCloser); ok && hc.CloseWrite() == nil {
		return
	}
	c.Close()
}

// pipe copies bidirectionally between a and b. A finished direction only
// half-closes its write side: a client that shuts down its write end after
// sending a request must still receive the response. Both ends are fully
// closed once both directions are done.
func pipe(a, b io.ReadWriteCloser) {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		io.Copy(b, a)
		closeWrite(b)
	}()

	go func() {
		defer wg.Done()
		io.Copy(a, b)
		closeWrite(a)
	}()

	wg.Wait()
	a.Close()
	b.Close()
}

func (p *Proxy) Run() error {
	if p.Handler == nil {
		return fmt.Errorf("proxy: Handler is required")
	}
	ln, err := net.Listen("tcp", p.ListenAddr)
	if err != nil {
		return err
	}
	defer ln.Close()

	log.Printf("[+] Starting proxy on %s", p.ListenAddr)
	return p.Serve(ln)
}

// Serve accepts connections until the listener is closed. Transient accept
// errors are retried with exponential backoff, mirroring net/http.Server.Serve.
func (p *Proxy) Serve(ln net.Listener) error {
	if p.Handler == nil {
		return fmt.Errorf("proxy: Handler is required")
	}

	var delay time.Duration
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return err
			}
			if delay == 0 {
				delay = acceptRetryDelay
			} else {
				delay *= 2
			}
			if delay > acceptMaxRetryDelay {
				delay = acceptMaxRetryDelay
			}
			log.Printf("Failed to accept connection: %v; retrying in %v", err, delay)
			time.Sleep(delay)
			continue
		}
		delay = 0
		go p.Handler(conn, p)
	}
}
