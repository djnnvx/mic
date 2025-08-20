package cmd

type MicCliOptions struct {

	/// Addr: address to listen to (Golang notation)
	Addr string

	/// ForwardTo: local port to forward call to
	ForwardTo int

	/// Verbose: enable verbose mode
	Verbose bool
}

func GetDefaultOptions() MicCliOptions {
	opts := MicCliOptions{
		Addr:      ":8080",
		ForwardTo: 1337,
		Verbose:   false,
	}

	return opts
}
