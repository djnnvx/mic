package main

import (
	"bufio"
	"log"
	"net"
	"net/http"
	"strings"

	utls "github.com/bogdanfinn/utls"
)

func main() {
	proxyAddr := "127.0.0.1:8080"
	targetAddr := "127.0.0.1:8443"

	// 1. Establish a TCP connection to the proxy.
	log.Printf("Connecting to proxy at %s", proxyAddr)
	proxyConn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		log.Fatalf("Failed to connect to proxy: %v", err)
	}
	defer proxyConn.Close()

	// 2. Manually send the HTTP CONNECT request to the proxy.
	connectReq, _ := http.NewRequest(http.MethodConnect, "https://"+targetAddr, nil)
	if err := connectReq.Write(proxyConn); err != nil {
		log.Fatalf("Failed to send CONNECT request to proxy: %v", err)
	}

	// 3. Read the proxy's response to the CONNECT request.
	reader := bufio.NewReader(proxyConn)
	resp, err := http.ReadResponse(reader, connectReq)
	if err != nil {
		log.Fatalf("Failed to read proxy response: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		log.Fatalf("Proxy returned non-200 status: %s", resp.Status)
	}
	log.Println("Proxy connection established.")

	// 4. Create a uTLS client from the proxied connection.
	// We'll use the Chrome 116 fingerprint for the client.
	utlsConfig := &utls.Config{ServerName: strings.Split(targetAddr, ":")[0]}
	uclient := utls.UClient(proxyConn, utlsConfig, utls.HelloRandomized, false, false, false)

	// 5. Perform the TLS handshake and get the handshake state.
	if err := uclient.Handshake(); err != nil {
		log.Fatalf("uTLS handshake failed: %v", err)
	}

	// 6. Extract and print key details from the server's certificate,
	// which are used to measure the server's JA4 fingerprint.
	log.Println("\n--- Server Fingerprint Measurement (JA4-like) ---")
	connState := uclient.ConnectionState()
	if len(connState.PeerCertificates) > 0 {
		cert := connState.PeerCertificates[0]
		log.Printf("Server Certificate Subject: %s", cert.Subject.CommonName)
		log.Printf("Server Certificate Issuer: %s", cert.Issuer.CommonName)
		log.Printf("Server Certificate Validity: %s to %s", cert.NotBefore, cert.NotAfter)
	}

	// 7. This section demonstrates how to use the tunneled connection to send a request.
	// The client will use the uTLS connection to send a simple HTTP GET request to the test server.
	log.Println("\n--- Sending Request to Test Server ---")
	req, _ := http.NewRequest(http.MethodGet, "https://"+targetAddr+"/", nil)
	if err := req.Write(uclient); err != nil {
		log.Fatalf("Failed to write request: %v", err)
	}

	// Read and print the response from the test server.
	resp, err = http.ReadResponse(bufio.NewReader(uclient), req)
	if err != nil {
		log.Fatalf("Failed to read response from server: %v", err)
	}
	defer resp.Body.Close()
	log.Printf("Server Response Status: %s", resp.Status)
}
