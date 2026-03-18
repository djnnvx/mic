package proxy

import (
	"crypto/x509"
	"io"
	"log"
	"net"
	"strings"
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

	handlers []Handler
}

type Handler func(conn net.Conn, p *Proxy)

func (p *Proxy) RegisterHandler(h Handler) {
	p.handlers = append(p.handlers, h)
}

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

	serverName := host
	if idx := strings.LastIndex(host, ":"); idx != -1 {
		serverName = host[:idx]
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
