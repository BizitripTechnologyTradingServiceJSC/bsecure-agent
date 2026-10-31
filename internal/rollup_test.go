package agent

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

var t0 = time.Date(2026, 10, 31, 10, 0, 30, 0, time.UTC)

func sshEv(ip, user string) Event {
	return Event{Source: "sshd", Type: "ssh_auth_failed", IP: ip, User: user,
		Line: "Oct 31 10:00:30 web-01 sshd[1]: Failed password for <user> from " + ip + " port 4000 ssh2"}
}

func TestAggregatorFoldsAttemptsAndHashesUsers(t *testing.T) {
	g := NewAggregator()
	for i := 0; i < 1000; i++ {
		g.Add(sshEv("203.0.113.9", []string{"root", "admin"}[i%2]), t0.Add(time.Duration(i)*time.Millisecond))
	}
	g.Add(sshEv("203.0.113.9", "root"), t0.Add(70*time.Second)) // next minute
	g.Add(Event{Source: "syslog", Type: "sudo_failed", Line: "sudo: authentication failure"}, t0)
	rs, rare := g.Drain(t0.Add(71 * time.Second))
	if len(rs) != 2 || len(rare) != 1 {
		t.Fatalf("rollups=%d rare=%d", len(rs), len(rare))
	}
	if rs[0].N != 1000 || rs[1].N != 1 {
		t.Fatalf("counts %d %d", rs[0].N, rs[1].N)
	}
	if rs[0].Sample != "sshd[1]: Failed password for <user> from <ip> port 4000 ssh2" {
		t.Fatalf("sample %q", rs[0].Sample)
	}
	b, _ := json.Marshal(rs)
	for _, secret := range []string{"root", "admin", "203.0.113.9\"" + ",\"src\":\"x"} {
		if strings.Contains(string(b), `"`+secret+`"`) {
			t.Fatalf("user name leaked: %s", b)
		}
	}
	if len(rs[0].Users) != 2 || rs[0].Users[0] != userToken("root") {
		t.Fatalf("users %v", rs[0].Users)
	}
	// Tokens must equal sha256(name)[:8 hex] — same as the panel computes
	if userToken("root") != "4813494d" {
		t.Fatalf("token %s", userToken("root"))
	}
}

func TestAggregatorDeltasAndRequeue(t *testing.T) {
	g := NewAggregator()
	for i := 0; i < 12; i++ {
		g.Add(sshEv("198.51.100.1", "a"), t0)
	}
	if !g.Hot() {
		t.Fatal("10 unsent attempts should ask for an early flush")
	}
	r1, _ := g.Drain(t0)
	if g.Hot() || r1[0].N != 12 || r1[0].Sample == "" {
		t.Fatal("first drain")
	}
	for i := 0; i < 3; i++ {
		g.Add(sshEv("198.51.100.1", "a"), t0.Add(5*time.Second))
	}
	r2, _ := g.Drain(t0.Add(10 * time.Second))
	if len(r2) != 1 || r2[0].N != 3 || r2[0].Sample != "" {
		t.Fatalf("second drain must send only the delta without repeating the sample: %+v", r2)
	}
	g.Requeue(r2, nil, t0.Add(10*time.Second)) // upload failed
	r3, _ := g.Drain(t0.Add(20 * time.Second))
	if len(r3) != 1 || r3[0].N != 3 {
		t.Fatalf("requeued delta lost: %+v", r3)
	}
	// finished minutes are forgotten once sent: memory is bounded by the last ~2 minutes
	g.Drain(t0.Add(10 * time.Minute))
	if g.Keys() != 0 {
		t.Fatalf("keys=%d", g.Keys())
	}
	// an hours-old rollup is not requeued (the panel would refuse it)
	g.Requeue([]Rollup{{B: t0.Add(-10 * time.Hour).Format(time.RFC3339), Type: "x", IP: "1.1.1.1", N: 5}}, nil, t0)
	if g.Keys() != 0 || g.Dropped != 5 {
		t.Fatalf("keys=%d dropped=%d", g.Keys(), g.Dropped)
	}
}

func TestAggregatorMemoryIsBounded(t *testing.T) {
	g := NewAggregator()
	for i := 0; i < maxKeys+5000; i++ {
		g.Add(sshEv(fmt.Sprintf("10.%d.%d.%d", i>>16&255, i>>8&255, i&255), "u"), t0)
	}
	if g.Keys() != maxKeys || g.Dropped != 5000 {
		t.Fatalf("keys=%d dropped=%d", g.Keys(), g.Dropped)
	}
	for i := 0; i < maxRare+10; i++ {
		g.Add(Event{Type: "sudo_failed", Line: "x"}, t0)
	}
	if len(g.rare) != maxRare {
		t.Fatal("rare events unbounded")
	}
	for i := 0; i < 1000; i++ {
		g.Add(sshEv("10.0.0.1", fmt.Sprint("user", i)), t0)
	}
	if n := len(g.m[rkey{t0.Unix() / 60 * 60, "ssh_auth_failed", "10.0.0.1"}].users); n != maxUsers {
		t.Fatalf("users per bucket %d", n)
	}
}

// The prefilters may let boring lines through but must never drop a line the parser would turn into an event.
func TestQuickFiltersNeverRejectWhatParsersAccept(t *testing.T) {
	nq := &nginxQuick{}
	now := time.Now()
	paths := []string{"/", "/index.html", "/.ENV", "/a/../b", "/WP-Login.php?x=1", "/%2E%2e/x", "/x?q=UNION%20SELECT", "/x?q=union+select", "/<SCRIPT>", "/%3Cscript", "/Shell.php",
		"/.git/config", "/phpMyAdmin/", "/vendor/phpunit/x", "/cgi-bin/x", "/actuator/env", "/boaform/x", "/.aws/credentials", "/etc/passwd", "/xmlrpc.php", "/eval-stdin.php", "/api/v1/users"}
	rnd := rand.New(rand.NewSource(1))
	for _, p := range paths {
		for _, st := range []string{"200", "401", "404", "500"} {
			line := fmt.Sprintf(`203.0.113.%d - - [31/Oct/2026:10:00:00 +0000] "GET %s HTTP/1.1" %s 12 "-" "UA"`, rnd.Intn(250), p, st)
			if ParseNginxAccess(line, now) != nil && !nq.Match([]byte(line)) {
				t.Errorf("nginx quick rejected: %s", line)
			}
		}
	}
	ssh := []string{
		"Oct 31 10:00:00 h sshd[1]: Failed password for root from 203.0.113.9 port 22 ssh2",
		"Oct 31 10:00:00 h sshd[1]: Failed publickey for invalid user x from 203.0.113.9 port 22 ssh2",
		"Oct 31 10:00:00 h sshd[1]: Invalid user bob from 203.0.113.9 port 22",
		"Oct 31 10:00:00 h sshd[1]: Connection closed by authenticating user root 203.0.113.9 port 22 [preauth]",
		"Oct 31 10:00:00 h sshd[1]: Disconnected from invalid user bob 203.0.113.9 port 22 [preauth]",
	}
	for _, l := range ssh {
		if NewSSHParser().Parse(l, now) == nil || !quickSSH([]byte(l)) {
			t.Errorf("ssh: %s", l)
		}
	}
	sys := []string{"sudo: pam_unix(sudo:auth): authentication failure; user=bob", "kernel: Out of memory: Killed process 1 (x)", "useradd[5]: new user: name=x", "kernel: foo[1]: segfault at 0 ip"}
	for _, l := range sys {
		if ParseSyslog(l, now) == nil || !quickSyslog([]byte(l)) {
			t.Errorf("syslog: %s", l)
		}
	}
	if quickSyslog([]byte("CRON[1]: (root) CMD (run-parts)")) || quickSSH([]byte("Accepted publickey for root")) {
		t.Error("boring line passed the filter")
	}
}

func TestTailEachHandlesPartialLinesRotationAndHugeLines(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "log")
	os.WriteFile(p, []byte("old\n"), 0o600)
	tl := &Tail{Path: p}
	var got []string
	collect := func() { got = nil; tl.Each(100, func(b []byte) { got = append(got, string(b)) }) }
	collect() // first call positions at the end
	f, _ := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0)
	f.WriteString("a\nb\npart")
	collect()
	if strings.Join(got, ",") != "a,b" {
		t.Fatalf("%v", got)
	}
	f.WriteString("ial\n" + strings.Repeat("x", 200_000) + "\nz\n")
	collect()
	if strings.Join(got, ",") != "partial,z" {
		t.Fatalf("huge line must be skipped, not delivered or stall the tail: %d lines", len(got))
	}
	os.Rename(p, p+".1")
	os.WriteFile(p, []byte("n1\nn2\n"), 0o600)
	collect()
	if strings.Join(got, ",") != "n1,n2" {
		t.Fatalf("after rotation: %v", got)
	}
	// load shedding
	big := bytes.Repeat([]byte("line of log text here\n"), 1000)
	g, _ := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0)
	g.Write(big)
	back, _ := tl.Each(10, func([]byte) {})
	if back == 0 {
		t.Fatal("backlog not reported")
	}
	if skipped := tl.SkipToEnd(); skipped != back {
		t.Fatalf("skipped %d backlog %d", skipped, back)
	}
	collect()
	if len(got) != 0 {
		t.Fatal("skipped lines came back")
	}
}

func TestFlushSendsRollupsAndRetriesAfterFailure(t *testing.T) {
	var mu sync.Mutex
	var bodies []map[string][]map[string]any
	paths := []string{}
	fail := true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if fail {
			w.WriteHeader(503)
			return
		}
		var m map[string][]map[string]any
		json.NewDecoder(r.Body).Decode(&m)
		bodies, paths = append(bodies, m), append(paths, r.URL.Path)
		w.Write([]byte("{}"))
	}))
	defer srv.Close()
	a := &Agent{cfg: Config{PanelURL: srv.URL}, http: srv.Client(), agg: NewAggregator()}
	now := time.Now()
	for i := 0; i < 50; i++ {
		a.agg.Add(sshEv("203.0.113.9", "root"), now)
	}
	a.agg.Add(Event{TS: now.Format(time.RFC3339), Source: "syslog", Type: "oom_kill", Line: "Out of memory"}, now)
	if a.FlushEvents() == nil {
		t.Fatal("expected failure")
	}
	fail = false
	for i := 0; i < 5; i++ {
		a.agg.Add(sshEv("203.0.113.9", "root"), now)
	}
	if err := a.FlushEvents(); err != nil {
		t.Fatal(err)
	}
	if len(paths) != 2 || paths[0] != "/agent/rollups" || paths[1] != "/agent/events" {
		t.Fatalf("paths %v", paths)
	}
	if n := bodies[0]["rollups"][0]["n"].(float64); n != 55 {
		t.Fatalf("n=%v (50 requeued + 5 new)", n)
	}
	if len(bodies[1]["events"]) != 1 {
		t.Fatal("rare event lost across the failed upload")
	}
}

// ---- cost ----

func benchLines(n int) [][]byte {
	rnd := rand.New(rand.NewSource(2))
	out := make([][]byte, n)
	for i := range out {
		switch rnd.Intn(10) {
		case 0:
			out[i] = []byte(`203.0.113.7 - - [31/Oct/2026:10:00:00 +0000] "GET /wp-login.php HTTP/1.1" 404 12 "-" "Mozilla/5.0"`)
		case 1:
			out[i] = []byte(`203.0.113.8 - - [31/Oct/2026:10:00:00 +0000] "POST /login HTTP/1.1" 401 12 "-" "Mozilla/5.0"`)
		default:
			out[i] = []byte(fmt.Sprintf(`198.51.100.%d - - [31/Oct/2026:10:00:00 +0000] "GET /static/app.%d.js HTTP/2.0" 200 5123 "https://example.com/" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/118 Safari/537.36"`, rnd.Intn(250), i))
		}
	}
	return out
}

func BenchmarkNginxLineFiltered(b *testing.B) {
	lines := benchLines(1000)
	nq := &nginxQuick{}
	g := NewAggregator()
	now := time.Now()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		l := lines[i%len(lines)]
		if !nq.Match(l) {
			continue
		}
		if e := ParseNginxAccess(string(l), now); e != nil {
			g.Add(*e, now)
		}
	}
}

func BenchmarkNginxLineParseAll(b *testing.B) { // what the agent did before: a regex on every line
	lines := benchLines(1000)
	now := time.Now()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		ParseNginxAccess(string(lines[i%len(lines)]), now)
	}
}
