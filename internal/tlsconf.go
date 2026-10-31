package agent

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"time"
)

// TLSConfig holds the agent side of mutual TLS with the Control Panel.
type TLSConfig struct {
	CAFile   string // private CA that signed the panel certificate (pins trust; system roots are not used)
	CertFile string // this agent's client certificate (CN = AGENT_NAME)
	KeyFile  string
	// AllowedCIDRs, when set, makes the agent refuse to talk to the panel unless the panel's address is inside one of
	// these ranges (e.g. NetBird's 100.64.0.0/10). A hijacked DNS name pointing to a public IP then fails closed.
	AllowedCIDRs []string
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
	if len(t.AllowedCIDRs) > 0 {
		allowed, err := parsePrefixes(t.AllowedCIDRs)
		if err != nil {
			return nil, err
		}
		tr.DialContext = overlayDialer(allowed)
	}
	return &http.Client{Timeout: 15 * time.Second, Transport: tr}, nil
}

func parsePrefixes(list []string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, c := range list {
		if c = strings.TrimSpace(c); c == "" {
			continue
		}
		p, err := netip.ParsePrefix(c)
		if err != nil {
			return nil, fmt.Errorf("bad PANEL_ALLOWED_CIDRS entry %q", c)
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

// overlayDialer resolves the target itself and connects only to an address inside the allowed ranges. TLS is still
// verified against the host name in the URL, because http.Transport does that after dialing.
func overlayDialer(allowed []netip.Prefix) func(ctx context.Context, network, addr string) (net.Conn, error) {
	d := &net.Dialer{Timeout: 10 * time.Second}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if err != nil {
			return nil, err
		}
		for _, ip := range ips {
			ip = ip.Unmap()
			for _, p := range allowed {
				if p.Contains(ip) {
					return d.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
				}
			}
		}
		return nil, fmt.Errorf("panel %s resolves to %v, none inside PANEL_ALLOWED_CIDRS: refusing to connect outside the VPN", host, ips)
	}
}
