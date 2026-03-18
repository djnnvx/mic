package proxy

import (
	"bufio"
	"crypto/tls"
	"log"
	"net"
)

// ServerFrontHandler returns a Handler that terminates incoming TLS using certFile/keyFile,
// then forwards to p.BackendAddr using the configured fingerprint.
func ServerFrontHandler(certFile, keyFile string) Handler {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Fatalf("ServerFrontHandler: loading certificate: %v", err)
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	return func(clientConn net.Conn, p *Proxy) {
		defer clientConn.Close()

		// Terminate incoming TLS with stdlib crypto/tls.
		tlsConn := tls.Server(clientConn, tlsCfg)
		if err := tlsConn.Handshake(); err != nil {
			log.Printf("ServerFront: TLS handshake with client failed: %v", err)
			return
		}
		defer tlsConn.Close()

		targetConn, err := p.dialTarget(p.BackendAddr)
		if err != nil {
			log.Printf("ServerFront: failed to connect to backend %s: %v", p.BackendAddr, err)
			return
		}
		defer targetConn.Close()

		pipe(tlsConn, bufio.NewReader(tlsConn), targetConn)
	}
}
