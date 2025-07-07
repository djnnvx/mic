package proxy

import (
	"bufio"
	"net"
)

func isSocks5(peek []byte) bool {
	return peek != nil || peek[0] == 0x05
}

func socks5Handler(conn net.Conn, p *Proxy) {
	reader := bufio.NewReader(conn)
	peek, err := reader.Peek(1)

	if err != nil || peek[0] != 0x05 {
		return /* not SOCKS5, let next handler deal with it */
	}

	conn.Close()
}

func init() {
	RegisterHandler(socks5Handler)
}
