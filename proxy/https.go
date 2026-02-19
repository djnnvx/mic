package proxy

import (
	"bufio"
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
	pipe(clientConn, reader, targetConn)
}
