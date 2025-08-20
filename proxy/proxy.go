package proxy

import (
	"log"
	"net"
)

type Proxy struct {
	ListenAddr string
	ForwardTo  int
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
			for _, h := range handlers {
				// Each handler processes the incoming connection.
				h(conn, p)
			}
		}()
	}
}
