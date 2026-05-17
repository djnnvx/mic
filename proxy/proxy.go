package proxy

import (
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net"
	"sync"

	utls "github.com/bogdanfinn/utls"
	"github.com/djnnvx/mic/fingerprint"
)

type Proxy struct {
	ListenAddr  string
	BackendAddr string // server-front: backend host:port
	CAPool      *x509.CertPool
	Fingerprint fingerprint.TLSApplier
	LocalCA     *LocalCA // client-front: MitM CA for TLS interception
	Handler     Handler
}

type Handler func(conn net.Conn, p *Proxy)

// dialTarget dials host (host:port) and returns a uTLS connection after a
// successful handshake. Falls back to HelloRandomized when no fingerprint is set.
func (p *Proxy) dialTarget(host string) (*utls.UConn, error) {
	tcpConn, err := net.Dial("tcp", host)
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

// pipe copies bidirectionally between client (reading from r) and target.
// When either direction finishes it closes that side so the other goroutine unblocks.
func pipe(client io.ReadWriteCloser, r io.Reader, target io.ReadWriteCloser) {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		io.Copy(target, r)
		target.Close()
	}()

	go func() {
		defer wg.Done()
		io.Copy(client, target)
		client.Close()
	}()

	wg.Wait()
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
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("Failed to accept connection: %v", err)
			continue
		}
		go p.Handler(conn, p)
	}
}
