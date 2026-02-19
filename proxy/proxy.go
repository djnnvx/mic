package proxy

import (
	"crypto/x509"
	"io"
	"log"
	"net"
	"strings"
	"sync"

	"github.com/djnnvx/mic/fingerprint"
	utls "github.com/refraction-networking/utls"
)

type Proxy struct {
	ListenAddr  string
	BackendAddr string // server-front: backend host:port
	CAPool      *x509.CertPool
	Fingerprint fingerprint.TLSApplier
	LocalCA     *LocalCA // client-front: MitM CA for TLS interception

	handlers []Handler
}

// Handler is a function that processes an incoming client connection.
type Handler func(conn net.Conn, p *Proxy)

// RegisterHandler adds a handler to the proxy.
func (p *Proxy) RegisterHandler(h Handler) {
	p.handlers = append(p.handlers, h)
}

// dialTarget dials host (host:port), performs a uTLS handshake using p.Fingerprint,
// and returns the ready-to-use connection. Falls back to HelloRandomized if no
// fingerprint is configured.
func (p *Proxy) dialTarget(host string) (*utls.UConn, error) {
	tcpConn, err := net.Dial("tcp", host)
	if err != nil {
		return nil, err
	}

	helloID := utls.HelloRandomized
	if p.Fingerprint != nil {
		helloID = p.Fingerprint.ClientHelloID()
	}

	serverName := host
	if idx := strings.LastIndex(host, ":"); idx != -1 {
		serverName = host[:idx]
	}

	cfg := &utls.Config{
		ServerName: serverName,
	}
	if p.CAPool != nil {
		cfg.RootCAs = p.CAPool
	}

	uconn := utls.UClient(tcpConn, cfg, helloID)
	if err := uconn.Handshake(); err != nil {
		uconn.Close()
		return nil, err
	}
	return uconn, nil
}

// pipe copies data bidirectionally between client (reading from r) and target,
// blocking until both directions are done. When either direction finishes it
// closes that side's connection so the other goroutine unblocks and exits.
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

// Run starts the proxy server and dispatches incoming connections to registered handlers.
func (p *Proxy) Run() error {
	ln, err := net.Listen("tcp", p.ListenAddr)
	if err != nil {
		return err
	}
	defer ln.Close()

	log.Printf("[+] Starting proxy on %s", p.ListenAddr)
	for {
		c, err := ln.Accept()
		if err != nil {
			log.Printf("Failed to accept connection: %v", err)
			continue
		}

		conn := c
		go func() {
			for _, h := range p.handlers {
				h(conn, p)
			}
		}()
	}
}
