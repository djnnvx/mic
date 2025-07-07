package proxy

import (
	"crypto/x509"
	"net"
)

type Proxy struct {
	ListenAddr string
	CAPool *x509.CertPool
}

// function is a function that processes an incoming client connection
type Handler func(conn net.Conn, p *Proxy)

// registry for all protocol handlers
var handlers []Handler

// adds a handler to the orchestrator
func RegisterHandler(h Handler) {
	handlers = append(handlers, h)
}

// Run starts the proxy server and orchestrates all protocol handlers
func (p *Proxy) Run() error {
	ln, err := net.Listen("tcp", p.ListenAddr)
	if err != nil {
		return err
	}

	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}

		conn := c
		go func() {
			for _, h := range handlers {
				h(conn, p)
			}
		}()
	}
}
