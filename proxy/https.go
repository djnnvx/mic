package proxy

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"

	utls "github.com/refraction-networking/utls"
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
	// If no port is specified by the client, use the `ForwardTo` port from our Proxy struct.
	host := req.URL.Host
	if !strings.Contains(host, ":") {
		host = fmt.Sprintf("%s:%d", host, p.ForwardTo)
	}

	log.Printf("Connecting to target: %s", host)
	targetConn, err := net.Dial("tcp", host)
	if err != nil {
		log.Printf("Failed to dial target %s: %v", host, err)
		return
	}
	defer targetConn.Close()

	// Create a uTLS client with the randomly selected fingerprint & perform handshake
	utlsConfig := &utls.Config{
		ServerName: strings.Split(host, ":")[0],
	}
	uclient := utls.UClient(targetConn, utlsConfig, utls.HelloRandomized)

	if err := uclient.Handshake(); err != nil {
		log.Printf("uTLS handshake failed with %s: %v", host, err)
		return
	}
	defer uclient.Close()

	clientConn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
	var wg sync.WaitGroup
	wg.Add(2)

	// Pipe data from the client to the target server.
	go func() {
		defer wg.Done()
		_, err := io.Copy(uclient, reader)
		if err != nil && err != io.EOF {
			log.Printf("Error copying from client to target: %v", err)
		}
	}()

	go func() {
		defer wg.Done()
		_, err := io.Copy(clientConn, uclient)
		if err != nil && err != io.EOF {
			log.Printf("Error copying from target to client: %v", err)
		}
	}()

	wg.Wait()
}
