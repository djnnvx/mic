package proxy

import (
	"bufio"
	"log"
	"net"
)

func backendHandler(conn net.Conn, p *Proxy) {
	defer conn.Close()
	reader := bufio.NewReader(conn)

	/* peek to determine protocol */
	peek, err := reader.Peek(1)
	if err != nil {
		log.Printf("[-] peek failed: %s\n", err.Error())
		return
	}

	if isSocks5(peek) {

	}
}

func init() {
	RegisterHandler(backendHandler)
}
