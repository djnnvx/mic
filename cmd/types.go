package cmd

type MicCliOptions struct {

	/// Port: port to listen to
	Port int

	/// Addr: address to listen to
	Addr string

	/// CaPath: custom CA certificate path (optional)
	CaPath string

	/// Verbose: enable verbose mode
	Verbose bool
}

func GetDefaultOptions() MicCliOptions {
	opts := MicCliOptions{
		Port:    8080,
		Addr:    "127.0.0.1",
		CaPath:  "",
		Verbose: false,
	}

	return opts
}
