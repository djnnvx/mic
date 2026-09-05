package cmd

import (
	"fmt"
	"log"
	"strings"

	"github.com/djnnvx/mic/fingerprint"
	"github.com/djnnvx/mic/proxy"
	"github.com/spf13/cobra"
)

func proxyURL(listen string) string {
	if strings.HasPrefix(listen, ":") {
		return "localhost" + listen
	}
	return listen
}

func newClientCmd() *cobra.Command {
	var (
		listen        string
		fpName        string
		caPath        string
		interceptCert string
		interceptKey  string
	)

	cmd := &cobra.Command{
		Use:   "client",
		Short: "HTTP CONNECT proxy with optional MitM interception",
		RunE: func(cmd *cobra.Command, args []string) error {
			p := &proxy.Proxy{ListenAddr: listen}

			if caPath != "" {
				pool, err := loadCAPool(caPath)
				if err != nil {
					return err
				}
				p.CAPool = pool
			}

			if fpName != "" {
				fp, err := fingerprint.ByName(fpName)
				if err != nil {
					return fmt.Errorf("loading fingerprint: %w", err)
				}
				p.Fingerprint = fp
				log.Printf("[+] Using TLS fingerprint: %s", fp.Name())
			}

			if (interceptCert == "") != (interceptKey == "") {
				return fmt.Errorf("--intercept-cert and --intercept-key must be given together")
			}
			if interceptCert != "" {
				ca, err := proxy.LoadOrGenerateCA(interceptCert, interceptKey)
				if err != nil {
					return fmt.Errorf("loading/generating intercept CA: %w", err)
				}
				p.LocalCA = ca
				log.Printf("[+] MitM CA ready. Import %s, then: curl --cacert %s -x http://%s https://<target>",
					interceptCert, interceptCert, proxyURL(listen))
			}

			log.Printf("[+] Mode: client (HTTP CONNECT proxy on %s)", listen)
			p.Handler = proxy.HttpsHandler
			return p.Run()
		},
	}

	cmd.Flags().StringVarP(&listen, "listen", "l", ":8080", "listen address")
	cmd.Flags().StringVarP(&fpName, "fingerprint", "f", "", "TLS fingerprint profile name (e.g. chrome-120)")
	cmd.Flags().StringVar(&caPath, "ca", "", "path to upstream CA certificate")
	cmd.Flags().StringVar(&interceptCert, "intercept-cert", "", "MitM CA cert path (enables interception)")
	cmd.Flags().StringVar(&interceptKey, "intercept-key", "", "MitM CA key path (enables interception)")

	return cmd
}
