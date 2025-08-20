package cmd

type MicCliOptions struct {

	/// Port: port to listen to
	Port int

	/// Addr: address to listen to
	Addr string

	/// ForwardTo: local port to forward call to
	ForwardTo int

	/// Verbose: enable verbose mode
	Verbose bool
}

func GetDefaultOptions() MicCliOptions {
	opts := MicCliOptions{
		Port:      8080,
		Addr:      "127.0.0.1",
		ForwardTo: 1337,
		Verbose:   false,
	}

	return opts
}
