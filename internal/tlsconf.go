package agent

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

// TLSConfig holds the agent side of mutual TLS with the Control Panel.
type TLSConfig struct {
	CAFile   string // private CA that signed the panel certificate (pins trust; system roots are not used)
	CertFile string // this agent's client certificate (CN = AGENT_NAME)
	KeyFile  string
}

// NewHTTPClient builds the client used for every panel call. Plain http is refused unless allowInsecure.
func NewHTTPClient(panelURL string, t TLSConfig, allowInsecure bool) (*http.Client, error) {
	if !strings.HasPrefix(panelURL, "https://") {
		if !allowInsecure {
			return nil, errors.New("PANEL_URL must be https:// (set ALLOW_INSECURE_HTTP=true only for local testing)")
		}
		return &http.Client{Timeout: 15 * time.Second}, nil
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if t.CAFile != "" {
		pem, err := os.ReadFile(t.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read PANEL_CA_FILE: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("PANEL_CA_FILE contains no certificates")
		}
		cfg.RootCAs = pool
	}
	if t.CertFile != "" || t.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(t.CertFile, t.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("load client certificate: %w", err)
		}
		cfg.Certificates = []tls.Certificate{cert}
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = cfg
	tr.Proxy = nil // never send the client certificate through an HTTP(S)_PROXY from the environment
	return &http.Client{Timeout: 15 * time.Second, Transport: tr}, nil
}
