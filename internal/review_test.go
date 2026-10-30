package agent

import (
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestCountSetElems(t *testing.T) {
	out := `{"nftables":[{"metainfo":{"version":"1.0.9"}},{"set":{"family":"inet","name":"blocklist4","table":"fwctl","type":"ipv4_addr","flags":["timeout"],
	"elem":[{"elem":{"val":"203.0.113.9","timeout":300,"expires":290}},{"elem":{"val":"203.0.113.10","timeout":300,"expires":100}}]}}]}`
	if n := CountSetElems(out); n != 2 {
		t.Fatalf("got %d", n)
	}
	if n := CountSetElems(`{"nftables":[{"set":{"name":"blocklist4"}}]}`); n != 0 {
		t.Fatalf("empty set: %d", n)
	}
}

func TestTailDetectsRotation(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "access.log")
	os.WriteFile(p, []byte("old1\nold2\n"), 0o644)
	tl := &Tail{Path: p}
	tl.Read(100) // init at end
	os.Rename(p, p+".1")
	// new file already bigger than the old offset
	os.WriteFile(p, []byte("new-line-number-1\nnew-line-number-2\n"), 0o644)
	lines, _ := tl.Read(100)
	if len(lines) != 2 || lines[0] != "new-line-number-1" {
		t.Fatalf("rotation missed: %q", lines)
	}
}

func TestUnblockAllowedForAllowlistedIPButBlockIsNot(t *testing.T) {
	g, _ := ParseGuard([]string{"198.51.100.7"})
	for _, tc := range []struct {
		action, ip string
		ok         bool
	}{{"unblock_ip", "198.51.100.7", true}, {"block_ip", "198.51.100.7", false}, {"block_ip", "172.68.1.1", false}, {"block_ip", "2606:4700::1", false}} {
		c := base()
		c.Action, c.Params.IP = tc.action, tc.ip
		pub, p, s := mk(t, c)
		_, err := Verify(pub, "srv", p, s, time.Now(), never, g)
		if (err == nil) != tc.ok {
			t.Errorf("%s %s: err=%v", tc.action, tc.ip, err)
		}
	}
}

func TestOutboxRetriesUntilPanelAccepts(t *testing.T) {
	var up atomic.Bool
	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !up.Load() {
			w.WriteHeader(503)
			return
		}
		if strings.Contains(r.URL.Path, "gone") {
			w.WriteHeader(409)
			return
		}
		got = append(got, r.URL.Path)
	}))
	defer srv.Close()
	dir := t.TempDir()
	a := &Agent{cfg: Config{PanelURL: srv.URL, StateDir: dir}, http: srv.Client()}
	a.report("aaaa", "reverted", "x")
	a.report("gone", "success", "")
	a.report("bbbb", "success", "")
	if len(got) != 0 || len(a.outbox) != 3 {
		t.Fatalf("should be queued: %v %d", got, len(a.outbox))
	}
	// survives restart
	b := &Agent{cfg: a.cfg, http: srv.Client()}
	b.loadOutbox()
	up.Store(true)
	b.FlushOutbox()
	if len(b.outbox) != 0 || strings.Join(got, ",") != "/agent/commands/aaaa/result,/agent/commands/bbbb/result" {
		t.Fatalf("delivered in order, 4xx dropped: %v left=%d", got, len(b.outbox))
	}
}

func TestRevertFailureBacksOff(t *testing.T) {
	m, f, _ := newMgr(t)
	f.sshdT = func() string { return "x11forwarding no\n" }
	m.Apply("aaaaaaaaaaaaaaaaaaaaaaaa", Change{"sshd", "X11Forwarding", "no"}, 30, false)
	f.nowOffset = time.Minute
	p := m.Due()[0]
	if m.RevertFailed(p) != 1 || len(m.Due()) != 0 {
		t.Fatal("must not be due again immediately")
	}
	f.nowOffset += 61 * time.Second
	if len(m.Due()) != 1 || m.RevertFailed(m.Due()[0]) != 2 {
		t.Fatal("second attempt after 1m")
	}
	f.nowOffset += 61 * time.Second
	if len(m.Due()) != 0 {
		t.Fatal("third attempt waits 2m")
	}
}

func TestRevertDueReportsFailureOnce(t *testing.T) {
	m, f, _ := newMgr(t)
	f.sshdT = func() string { return "x11forwarding no\n" }
	var posts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { posts.Add(1) }))
	defer srv.Close()
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	a := &Agent{cfg: Config{PanelURL: srv.URL, StateDir: t.TempDir()}, cm: m, http: srv.Client(), pub: pub}
	m.Apply("aaaaaaaaaaaaaaaaaaaaaaaa", Change{"sshd", "X11Forwarding", "no"}, 30, false)
	f.failOn = "systemctl" // reload keeps failing
	for i := 0; i < 5; i++ {
		f.nowOffset += 2 * time.Hour
		a.RevertDue()
	}
	if posts.Load() != 1 {
		t.Fatalf("failure reported %d times", posts.Load())
	}
}
