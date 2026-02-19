package fingerprint

// TCPApplier is reserved for future TCP-level fingerprinting support
// (TCP window size, TTL, MSS, timestamps, etc.).
//
// Future interface outline:
//
//	type TCPApplier interface {
//	    Applier
//	    Apply(fd uintptr) error
//	}
