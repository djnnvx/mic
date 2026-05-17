package proxy

import (
	"bufio"
	"crypto/tls"
	"log"
	"net"
	"net/http"
)

// parseAuthority extracts the server name and a dial-ready "host:port" from
// a CONNECT request's authority. If the input lacks an explicit port (rare,
// since CONNECT requires one), 443 is assumed. IPv6 literals in brackets are
// handled (e.g. "[::1]:443" -> "::1", "[::1]:443").
func parseAuthority(authority string) (server, hostPort string) {
	if h, _, err := net.SplitHostPort(authority); err == nil {
		return h, authority
	}
	server = authority
	if n := len(server); n >= 2 && server[0] == '[' && server[n-1] == ']' {
		server = server[1 : n-1]
	}
	return server, net.JoinHostPort(server, "443")
}

func HttpsHandler(clientConn net.Conn, p *Proxy) {
	defer clientConn.Close()

	reader := bufio.NewReader(clientConn)
	req, err := http.ReadRequest(reader)
	if err != nil {
		log.Printf("Failed to read client request: %v", err)
		return
	}

	if req.Method != http.MethodConnect {
		log.Printf("Received non-CONNECT request: %s %s", req.Method, req.Host)
		return
	}

	serverName, host := parseAuthority(req.URL.Host)

	log.Printf("Connecting to target: %s", host)
	targetConn, err := p.dialTarget(host)
	if err != nil {
		log.Printf("Failed to connect to target %s: %v", host, err)
		return
	}
	defer targetConn.Close()

	clientConn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))

	if p.LocalCA != nil {
		cert, err := p.LocalCA.issueCert(serverName)
		if err != nil {
			log.Printf("Failed to issue cert for %s: %v", serverName, err)
			return
		}

		// Mirror the ALPN negotiated with the target so the client uses the same
		// application protocol. Without this, Chrome-fingerprint uTLS often
		// negotiates h2 with the target while the client sends HTTP/1.1, causing
		// an immediate protocol error.
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
		pipe(tlsClient, targetConn)
		return
	}

	pipe(&bufferedConn{r: reader, Conn: clientConn}, targetConn)
}
