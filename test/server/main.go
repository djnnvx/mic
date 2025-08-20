package main

import (
	"fmt"
	"log"
	"net/http"
)

func main() {
	// 1. Define the handler function for all requests.
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Received request for: %s %s", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "Hello! You have reached the test server. All is well.")
	})

	// 2. Set the address for the server to listen on.
	addr := "127.0.0.1:8443"

	// 3. Start the HTTPS server.
	log.Printf("Starting HTTPS test server on %s", addr)
	err := http.ListenAndServeTLS(addr, "cert.pem", "key.pem", nil)
	if err != nil {
		log.Fatalf("Test server failed: %v", err)
	}
}
