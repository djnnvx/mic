// Package fingerprint provides interfaces and implementations for controlling
// outbound connection fingerprints (TLS ClientHello, TCP socket options, etc.).
package fingerprint

import utls "github.com/bogdanfinn/utls"

// Applier is the base interface for all fingerprint types.
type Applier interface {
	Name() string
}

// TLSApplier controls the uTLS ClientHello fingerprint for outbound connections.
type TLSApplier interface {
	Applier
	ClientHelloID() utls.ClientHelloID
}

// TCPApplier will control TCP socket options (window size, TTL, MSS, etc.).
// Left for a future implementation.
//
// type TCPApplier interface {
//     Applier
//     Apply(fd uintptr) error
// }
