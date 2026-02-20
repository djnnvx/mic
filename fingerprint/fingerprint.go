// Package fingerprint provides interfaces and implementations for controlling
// outbound TLS connection fingerprints.
package fingerprint

import utls "github.com/refraction-networking/utls"

type Applier interface {
	Name() string
}

// TLSApplier controls the uTLS ClientHello fingerprint for outbound connections.
type TLSApplier interface {
	Applier
	ClientHelloID() utls.ClientHelloID
}
