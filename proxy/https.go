package proxy

import (
	"bufio"
	"crypto/tls"
	"log"
	"net"
	"net/http"
	"strings"
)

func HttpsHandler(clientConn net.Conn, p *Proxy) {
	defer clientConn.Close()

	// Read the first line of the request to check for the CONNECT method.
	reader := bufio.NewReader(clientConn)
	req, err := http.ReadRequest(reader)
	if err != nil {
		log.Printf("Failed to read client request: %v", err)
		return
	}

	// An HTTPS proxy relies on the HTTP CONNECT method.
	if req.Method != http.MethodConnect {
		log.Printf("Received non-CONNECT request: %s %s", req.Method, req.Host)
		return
	}

	// The Host field contains the destination host and port.
	// Default to :443 if no port is specified.
	host := req.URL.Host
	if !strings.Contains(host, ":") {
		host = host + ":443"
	}

	log.Printf("Connecting to target: %s", host)
	targetConn, err := p.dialTarget(host)
	if err != nil {
		log.Printf("Failed to connect to target %s: %v", host, err)
		return
	}
	defer targetConn.Close()

	clientConn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))

	// MitM path: terminate TLS from the client using a per-host certificate
	// issued by the local CA, then pipe decrypted traffic over the already-
	// established uTLS connection to the target.
	if p.LocalCA != nil {
		serverName := host
		if idx := strings.LastIndex(host, ":"); idx != -1 {
			serverName = host[:idx]
		}

		cert, err := p.LocalCA.issueCert(serverName)
		if err != nil {
			log.Printf("Failed to issue cert for %s: %v", serverName, err)
			return
		}

		// Mirror the ALPN negotiated with the target so the client uses the
		// same application protocol (e.g. h2 vs http/1.1). Without this,
		// Chrome-fingerprint uTLS often negotiates h2 with the target while
		// the client sends HTTP/1.1, causing an immediate protocol error.
		nextProtos := []string{"http/1.1"}
		if proto := targetConn.ConnectionState().NegotiatedProtocol; proto != "" {
			nextProtos = []string{proto}
		}

		tlsClient := tls.Server(clientConn, &tls.Config{
			Certificates: []tls.Certificate{cert},
			NextProtos:   nextProtos,
		})
		if err := tlsClient.Handshake(); err != nil {
			log.Printf("TLS handshake with client failed for %s: %v", serverName, err)
			return
		}
		defer tlsClient.Close()

		log.Printf("MitM tunnel established for %s (proto: %s)", serverName, tlsClient.ConnectionState().NegotiatedProtocol)

		// Both sides are now on the same protocol — pipe plaintext between them.
		pipe(tlsClient, tlsClient, targetConn)
		return
	}

	// No LocalCA: pipe raw bytes (client must not speak TLS after CONNECT).
	pipe(clientConn, reader, targetConn)
}
