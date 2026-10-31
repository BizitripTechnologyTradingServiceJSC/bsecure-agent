package agent

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type pki struct {
	caCert *x509.Certificate
	caKey  *ecdsa.PrivateKey
	caPEM  []byte
}

func newPKI(t *testing.T) *pki {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test-ca"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return &pki{c, k, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

func (p *pki) issue(t *testing.T, cn string, server bool) (certPEM, keyPEM []byte) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	if server {
		tpl.ExtKeyUsage, tpl.IPAddresses = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, []net.IP{net.ParseIP("127.0.0.1")}
	} else {
		tpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, p.caCert, &k.PublicKey, p.caKey)
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := x509.MarshalECPrivateKey(k)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb})
}

func TestMutualTLSClient(t *testing.T) {
	p := newPKI(t)
	sc, sk := p.issue(t, "panel", true)
	srvCert, _ := tls.X509KeyPair(sc, sk)
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(p.caPEM)
	var gotCN string
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCN = r.TLS.PeerCertificates[0].Subject.CommonName
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{srvCert}, ClientCAs: pool, ClientAuth: tls.RequireAndVerifyClientCert}
	srv.StartTLS()
	defer srv.Close()

	dir := t.TempDir()
	w := func(n string, b []byte) string { p := filepath.Join(dir, n); os.WriteFile(p, b, 0o600); return p }
	cc, ck := p.issue(t, "lab-01", false)
	conf := TLSConfig{CAFile: w("ca.crt", p.caPEM), CertFile: w("a.crt", cc), KeyFile: w("a.key", ck)}

	c, err := NewHTTPClient(srv.URL, conf, false)
	if err != nil {
		t.Fatal(err)
	}
	if res, err := c.Get(srv.URL); err != nil || res.StatusCode != 200 || gotCN != "lab-01" {
		t.Fatalf("mTLS request failed: %v cn=%q", err, gotCN)
	}
	// without a client cert the server rejects the handshake
	noCert, _ := NewHTTPClient(srv.URL, TLSConfig{CAFile: conf.CAFile}, false)
	if _, err := noCert.Get(srv.URL); err == nil {
		t.Fatal("request without client cert succeeded")
	}
	// panel cert from a different CA is not trusted (no fallback to system roots)
	other := newPKI(t)
	bad, _ := NewHTTPClient(srv.URL, TLSConfig{CAFile: w("other.crt", other.caPEM), CertFile: conf.CertFile, KeyFile: conf.KeyFile}, false)
	if _, err := bad.Get(srv.URL); err == nil {
		t.Fatal("untrusted panel certificate accepted")
	}
}

func TestPlainHTTPRefusedByDefault(t *testing.T) {
	if _, err := NewHTTPClient("http://panel", TLSConfig{}, false); err == nil {
		t.Fatal("http accepted")
	}
	if _, err := NewHTTPClient("http://panel", TLSConfig{}, true); err != nil {
		t.Fatal(err)
	}
}
