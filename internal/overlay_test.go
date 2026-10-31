package agent

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestOverlayAddressesAreNeverBlocked(t *testing.T) {
	a, err := New(Config{OverlayCIDRs: []string{"100.64.0.0/10"}, PanelURL: "http://x", AllowInsecure: true, StateDir: t.TempDir()}, &NFT{DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, ip := range []string{"100.64.0.5", "100.100.1.1", "100.127.255.254"} {
		if err := a.guard.CheckIP(netip.MustParseAddr(ip)); err == nil || !strings.Contains(err.Error(), "overlay") {
			t.Errorf("%s: %v", ip, err)
		}
	}
	if err := a.guard.CheckIP(netip.MustParseAddr("100.128.0.1")); err != nil {
		t.Errorf("address just outside the overlay range must stay blockable: %v", err)
	}
	if _, err := New(Config{OverlayCIDRs: []string{"nonsense"}, PanelURL: "http://x", AllowInsecure: true}, &NFT{DryRun: true}); err == nil {
		t.Error("bad OVERLAY_CIDRS must be a startup error")
	}
	// a signed block command for a peer is rejected by Verify, not just by the firewall layer
	c := base()
	c.Params.IP = "100.64.9.9"
	pub, p, s := mk(t, c)
	if _, err := Verify(pub, "srv", p, s, time.Now(), never, a.guard); err == nil {
		t.Error("block of an overlay peer accepted")
	}
}

func TestAgentTalksToPanelOnlyInsideAllowedRange(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) }))
	defer srv.Close() // listens on 127.0.0.1

	// panel address outside the allowed (NetBird) range: connection refused before any bytes are sent
	outside, err := NewHTTPClient("https://panel", TLSConfig{AllowedCIDRs: []string{"100.64.0.0/10"}}, false)
	if err != nil {
		t.Fatal(err)
	}
	tr := outside.Transport.(*http.Transport)
	if _, err := tr.DialContext(t.Context(), "tcp", strings.TrimPrefix(srv.URL, "http://")); err == nil || !strings.Contains(err.Error(), "outside the VPN") {
		t.Fatalf("dial outside the allowed range must fail closed: %v", err)
	}
	// the same address inside an allowed range connects
	inside, _ := NewHTTPClient("https://panel", TLSConfig{AllowedCIDRs: []string{"100.64.0.0/10", "127.0.0.0/8"}}, false)
	conn, err := inside.Transport.(*http.Transport).DialContext(t.Context(), "tcp", strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatalf("dial inside the allowed range: %v", err)
	}
	conn.Close()
	// a host name resolving to a loopback address is judged by the address it resolves to, not by the name
	if _, err := tr.DialContext(t.Context(), "tcp", "localhost:"+strings.Split(srv.URL, ":")[2]); err == nil {
		t.Fatal("localhost must not pass a 100.64.0.0/10-only policy")
	}
	if _, err := NewHTTPClient("https://panel", TLSConfig{AllowedCIDRs: []string{"bogus"}}, false); err == nil {
		t.Fatal("bad PANEL_ALLOWED_CIDRS must be a startup error")
	}
}
