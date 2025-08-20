package proxy

import (
	"crypto/x509"
	"log"
	"net"
)

type Proxy struct {
	ListenAddr string
	ForwardTo  int
	CAPool     *x509.CertPool

	handlers []Handler
}

// function is a function that processes an incoming client connection
type Handler func(conn net.Conn, p *Proxy)

// adds a handler to the orchestrator
func (p *Proxy) RegisterHandler(h Handler) {
	p.handlers = append(p.handlers, h)
}

func (p *Proxy) AddCertificate(cert *x509.CertPool) {
	p.CAPool = cert
}

// Run starts the proxy server and orchestrates all protocol handlers
func (p *Proxy) Run() error {
	ln, err := net.Listen("tcp", p.ListenAddr)
	if err != nil {
		return err
	}
	defer ln.Close()

	log.Printf("[+] Starting proxy on %s, forwarding to port %d", p.ListenAddr, p.ForwardTo)
	for {
		c, err := ln.Accept()
		if err != nil {
			log.Printf("Failed to accept connection: %v", err)
			continue
		}

		conn := c
		go func() {
			for _, h := range p.handlers {
				// Each handler processes the incoming connection.
				// It will get discarded by a handler if it doesn't support it.
				h(conn, p)
			}
		}()
	}
}
