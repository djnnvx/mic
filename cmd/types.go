package cmd

type MicCliOptions struct {
	ConfigPath string
}

func GetDefaultOptions() MicCliOptions {
	return MicCliOptions{
		ConfigPath: "mic.toml",
	}
}
