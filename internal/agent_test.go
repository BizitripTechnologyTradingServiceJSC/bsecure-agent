package agent

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func mk(t *testing.T, c Command) (ed25519.PublicKey, string, string) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	b, _ := json.Marshal(c)
	return pub, string(b), base64.StdEncoding.EncodeToString(ed25519.Sign(priv, b))
}

func base() Command {
	return Command{ID: "1", ServerID: "srv", Action: "block_ip", Params: Params{IP: "203.0.113.9", TTLSeconds: 3600},
		ExpiresAt: time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano), Nonce: "n"}
}

func never(string) bool { return false }

func TestVerify(t *testing.T) {
	g, _ := ParseGuard([]string{"198.51.100.0/24"})
	cases := []struct {
		name string
		mut  func(*Command)
		want string
	}{
		{"ok", func(c *Command) {}, ""},
		{"wrong server", func(c *Command) { c.ServerID = "other" }, "different server"},
		{"expired", func(c *Command) { c.ExpiresAt = time.Now().Add(-time.Minute).UTC().Format(time.RFC3339Nano) }, "expired"},
		{"bad action", func(c *Command) { c.Action = "exec" }, "not allowed"},
		{"allowlisted", func(c *Command) { c.Params.IP = "198.51.100.7" }, "allowlist"},
		{"loopback", func(c *Command) { c.Params.IP = "127.0.0.1" }, "loopback"},
		{"ttl", func(c *Command) { c.Params.TTLSeconds = 5 }, "ttl"},
		{"bad ip", func(c *Command) { c.Params.IP = "1.2.3.4; rm -rf /" }, "invalid ip"},
	}
	for _, tc := range cases {
		c := base()
		tc.mut(&c)
		pub, p, s := mk(t, c)
		_, err := Verify(pub, "srv", p, s, time.Now(), never, g)
		if tc.want == "" && err != nil || tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)) {
			t.Errorf("%s: got %v want %q", tc.name, err, tc.want)
		}
	}
}

func TestSignatureAndReplay(t *testing.T) {
	g, _ := ParseGuard(nil)
	pub, p, s := mk(t, base())
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := Verify(other, "srv", p, s, time.Now(), never, g); err == nil {
		t.Fatal("wrong key accepted")
	}
	if _, err := Verify(pub, "srv", p+" ", s, time.Now(), never, g); err == nil {
		t.Fatal("tampered payload accepted")
	}
	if _, err := Verify(pub, "srv", p, s, time.Now(), func(string) bool { return true }, g); err == nil {
		t.Fatal("replay accepted")
	}
}

func TestDryRunAndNFT(t *testing.T) {
	var calls []string
	run := func(in, name string, args ...string) (string, error) { calls = append(calls, in); return "", nil }
	dry := &NFT{DryRun: true, Run: run}
	out, _ := dry.Block(netip.MustParseAddr("203.0.113.9"), 60)
	if !strings.HasPrefix(out, "DRY-RUN") || len(calls) != 0 {
		t.Fatalf("dry run touched host: %q %v", out, calls)
	}
	live := &NFT{Run: run}
	live.Block(netip.MustParseAddr("2001:db8::1"), 120)
	if len(calls) != 1 || calls[0] != "add element inet fwctl blocklist6 { 2001:db8::1 timeout 120s }\n" {
		t.Fatalf("unexpected nft input: %v", calls)
	}
	p, _ := ParseGuard([]string{"10.0.0.1"})
	if s := SetupScript(p.Allow); !strings.Contains(s, "ip saddr 10.0.0.1/32 accept") {
		t.Fatalf("allowlist missing from setup: %s", s)
	}
}

func TestParseSSH(t *testing.T) {
	l := "Oct 29 10:00:00 h sshd[1]: Failed password for invalid user admin from 203.0.113.9 port 4242 ssh2"
	e := ParseSSH(l, time.Now())
	if e == nil || e.IP != "203.0.113.9" || e.User != "admin" || strings.Contains(e.Line, "admin") {
		t.Fatalf("bad parse: %+v", e)
	}
	if ParseSSH("Accepted publickey for bob from 1.2.3.4 port 1", time.Now()) != nil {
		t.Fatal("should ignore success")
	}
}
