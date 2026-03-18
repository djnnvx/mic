package cmd

import (
	"crypto/x509"
	"log"
	"os"

	"github.com/djnnvx/mic/fingerprint"
	"github.com/djnnvx/mic/proxy"
	"github.com/spf13/cobra"
)

func newServerCmd() *cobra.Command {
	var (
		listen  string
		backend string
		fpName  string
		caPath  string
		cert    string
		key     string
	)

	cmd := &cobra.Command{
		Use:   "server",
		Short: "TLS termination proxy with upstream fingerprinting",
		RunE: func(cmd *cobra.Command, args []string) error {
			if backend == "" {
				log.Fatal("[!] --backend is required for server mode")
			}
			if cert == "" || key == "" {
				log.Fatal("[!] --cert and --key are required for server mode")
			}

			p := &proxy.Proxy{
				ListenAddr:  listen,
				BackendAddr: backend,
			}

			if caPath != "" {
				caCert, err := os.ReadFile(caPath)
				if err != nil {
					log.Fatalf("[!] Failed to read CA certificate: %v", err)
				}
				pool := x509.NewCertPool()
				pool.AppendCertsFromPEM(caCert)
				p.CAPool = pool
			}

			if fpName != "" {
				fp, err := fingerprint.ByName(fpName)
				if err != nil {
					log.Fatalf("[!] Failed to load fingerprint: %v", err)
				}
				p.Fingerprint = fp
				log.Printf("[+] Using TLS fingerprint: %s", fp.Name())
			}

			log.Printf("[+] Mode: server (TLS termination → backend %s)", backend)
			p.RegisterHandler(proxy.ServerFrontHandler(cert, key))
			return p.Run()
		},
	}

	cmd.Flags().StringVarP(&listen, "listen", "l", ":8080", "listen address")
	cmd.Flags().StringVarP(&backend, "backend", "b", "", "backend host:port (required)")
	cmd.Flags().StringVarP(&fpName, "fingerprint", "f", "", "TLS fingerprint profile name (e.g. chrome-120)")
	cmd.Flags().StringVar(&caPath, "ca", "", "path to upstream CA certificate")
	cmd.Flags().StringVar(&cert, "cert", "", "TLS certificate for incoming termination (required)")
	cmd.Flags().StringVar(&key, "key", "", "TLS key for incoming termination (required)")

	return cmd
}
