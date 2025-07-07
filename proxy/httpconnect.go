package proxy

import (
	"bufio"
	"net"
	"strings"
)

func httpConnectHandler(conn net.Conn, p *Proxy) {
	reader := bufio.NewReader(conn)
	line, err := reader.Peek(7)

	if err != nil || !strings.HasPrefix(string(line), "CONNECT") {
		return /* not HTTP, let next handler deal with it */
	}

	conn.Close()
}

func init() {
	RegisterHandler(httpConnectHandler)
}
