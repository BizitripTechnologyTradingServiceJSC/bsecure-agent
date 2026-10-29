package agent

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

type fakeSys struct {
	calls     []string
	failOn    string // substring of "name args" that should fail
	sshdT     func() string
	nowOffset time.Duration
}

func (f *fakeSys) run(_ string, name string, args ...string) (string, error) {
	cmd := name + " " + strings.Join(args, " ")
	f.calls = append(f.calls, cmd)
	if f.failOn != "" && strings.Contains(cmd, f.failOn) {
		return "boom", errors.New("exit 1")
	}
	if cmd == "sshd -T" && f.sshdT != nil {
		return f.sshdT(), nil
	}
	return "", nil
}

func (f *fakeSys) called(sub string) bool {
	for _, c := range f.calls {
		if strings.Contains(c, sub) {
			return true
		}
	}
	return false
}

func newMgr(t *testing.T) (*ConfigManager, *fakeSys, string) {
	root := t.TempDir()
	f := &fakeSys{}
	m := &ConfigManager{Root: root, Run: f.run, StateDir: t.TempDir(), Sleep: func(time.Duration) {}}
	now := time.Now()
	m.Now = func() time.Time { return now.Add(f.nowOffset) }
	write(t, root, "/etc/ssh/sshd_config", "Include /etc/ssh/sshd_config.d/*.conf\nPermitRootLogin yes\n")
	write(t, root, "/home/bob/.ssh/authorized_keys", "ssh-ed25519 AAAA bob\n")
	return m, f, root
}

func read(t *testing.T, root, rel string) string {
	b, err := os.ReadFile(root + rel)
	if err != nil {
		return "<absent>"
	}
	return string(b)
}

func TestSSHDChangeConfirmAndRevert(t *testing.T) {
	m, f, root := newMgr(t)
	f.sshdT = func() string { return "permitrootlogin no\n" }
	st, out := m.Apply("aaaaaaaaaaaaaaaaaaaaaaaa", Change{"sshd", "PermitRootLogin", "no"}, 60, false)
	if st != "pending_confirm" || !strings.Contains(out, "auto-revert") {
		t.Fatalf("%s %s", st, out)
	}
	if got := read(t, root, sshdDropIn); !strings.Contains(got, "PermitRootLogin no") {
		t.Fatalf("drop-in: %q", got)
	}
	if !f.called("sshd -t") || !f.called("systemctl reload-or-restart ssh") {
		t.Fatalf("validate/reload missing: %v", f.calls)
	}
	if len(m.Due()) != 0 {
		t.Fatal("not due yet")
	}
	// second change to same software is refused while one awaits confirmation
	if st, _ := m.Apply("bbbbbbbbbbbbbbbbbbbbbbbb", Change{"sshd", "X11Forwarding", "no"}, 60, false); st != "failed" {
		t.Fatal("concurrent change allowed")
	}
	// not confirmed: deadline passes -> revert removes the file we created
	f.nowOffset = 2 * time.Minute
	due := m.Due()
	if len(due) != 1 {
		t.Fatal("should be due")
	}
	if err := m.Revert(due[0]); err != nil {
		t.Fatal(err)
	}
	if read(t, root, sshdDropIn) != "<absent>" || len(m.load()) != 0 {
		t.Fatal("revert incomplete")
	}
}

func TestConfirmCancelsRevert(t *testing.T) {
	m, f, _ := newMgr(t)
	f.sshdT = func() string { return "x11forwarding no\n" }
	m.Apply("cccccccccccccccccccccccc", Change{"sshd", "X11Forwarding", "no"}, 60, false)
	if !m.Confirm("cccccccccccccccccccccccc") || m.Confirm("cccccccccccccccccccccccc") {
		t.Fatal("confirm semantics")
	}
	f.nowOffset = time.Hour
	if len(m.Due()) != 0 {
		t.Fatal("confirmed change must not revert")
	}
}

func TestRollbackOnValidateAndVerifyFailure(t *testing.T) {
	m, f, root := newMgr(t)
	f.failOn = "sshd -t"
	st, out := m.Apply("dddddddddddddddddddddddd", Change{"sshd", "MaxAuthTries", "3"}, 60, false)
	if st != "failed" || !strings.Contains(out, "restored") || read(t, root, sshdDropIn) != "<absent>" || f.called("systemctl") {
		t.Fatalf("validate failure must restore without reload: %s %s %v", st, out, f.calls)
	}
	// effective value differs (overridden elsewhere) -> rolled back and reloaded again
	f.failOn, f.calls = "", nil
	f.sshdT = func() string { return "permitrootlogin yes\n" }
	st, out = m.Apply("eeeeeeeeeeeeeeeeeeeeeeee", Change{"sshd", "PermitRootLogin", "no"}, 60, false)
	n := 0
	for _, c := range f.calls {
		if strings.HasPrefix(c, "systemctl") {
			n++
		}
	}
	if st != "failed" || !strings.Contains(out, "overridden") || read(t, root, sshdDropIn) != "<absent>" || n != 2 {
		t.Fatalf("verify failure: %s %s reloads=%d", st, out, n)
	}
}

func TestLockoutGuardAndDryRun(t *testing.T) {
	m, f, root := newMgr(t)
	os.Remove(root + "/home/bob/.ssh/authorized_keys")
	if st, out := m.Apply("ffffffffffffffffffffffff", Change{"sshd", "PasswordAuthentication", "no"}, 60, false); st != "failed" || !strings.Contains(out, "lock") {
		t.Fatalf("%s %s", st, out)
	}
	write(t, root, "/home/bob/.ssh/authorized_keys", "ssh-ed25519 AAAA bob\n")
	st, out := m.Apply("ffffffffffffffffffffffff", Change{"sshd", "PasswordAuthentication", "no"}, 60, true)
	if st != "dry_run" || !strings.Contains(out, "+ PasswordAuthentication no") || read(t, root, sshdDropIn) != "<absent>" || len(f.calls) != 0 {
		t.Fatalf("dry run must not touch anything: %s %s", st, out)
	}
	// no Include => refuse rather than guess
	write(t, root, "/etc/ssh/sshd_config", "PermitRootLogin yes\n")
	if st, out := m.Apply("ffffffffffffffffffffffff", Change{"sshd", "X11Forwarding", "no"}, 60, false); st != "failed" || !strings.Contains(out, "Include") {
		t.Fatalf("%s %s", st, out)
	}
}

func TestNginxEditsAllOccurrencesOrCreatesDropIn(t *testing.T) {
	m, _, root := newMgr(t)
	write(t, root, "/etc/nginx/nginx.conf", "http {\n    ssl_protocols TLSv1 TLSv1.1 TLSv1.2 TLSv1.3;\n    # server_tokens on;\n    include /etc/nginx/conf.d/*.conf;\n}\n")
	write(t, root, "/etc/nginx/sites-enabled/a", "server { ssl_protocols TLSv1.2; }\n")
	st, out := m.Apply("111111111111111111111111", Change{"nginx", "ssl_protocols", "TLSv1.2 TLSv1.3"}, 60, false)
	if st != "pending_confirm" {
		t.Fatalf("%s %s", st, out)
	}
	if got := read(t, root, "/etc/nginx/nginx.conf"); !strings.Contains(got, "    ssl_protocols TLSv1.2 TLSv1.3;") || !strings.Contains(got, "# server_tokens on;") {
		t.Fatalf("nginx.conf: %s", got)
	}
	if !strings.Contains(read(t, root, "/etc/nginx/sites-enabled/a"), "ssl_protocols TLSv1.2 TLSv1.3;") {
		t.Fatal("site not updated")
	}
	m.Confirm("111111111111111111111111")
	// server_tokens only appears in a comment -> new drop-in
	st, _ = m.Apply("222222222222222222222222", Change{"nginx", "server_tokens", "off"}, 60, false)
	if st != "pending_confirm" || !strings.Contains(read(t, root, nginxDropIn), "server_tokens off;") {
		t.Fatalf("%s %s", st, read(t, root, nginxDropIn))
	}
}

func TestTinyproxyListReplace(t *testing.T) {
	m, _, root := newMgr(t)
	write(t, root, "/etc/tinyproxy/tinyproxy.conf", "Port 8888\nAllow 0.0.0.0/0\nallow 10.0.0.0/8\nLogLevel Info\n")
	write(t, root, "/proc/77/comm", "tinyproxy\n")
	st, out := m.Apply("333333333333333333333333", Change{"tinyproxy", "Allow", "203.0.113.5,198.51.100.0/24"}, 60, false)
	if st != "pending_confirm" {
		t.Fatalf("%s %s", st, out)
	}
	got := read(t, root, "/etc/tinyproxy/tinyproxy.conf")
	if strings.Contains(got, "0.0.0.0/0") || !strings.Contains(got, "Allow 203.0.113.5\nAllow 198.51.100.0/24") || !strings.Contains(got, "Port 8888") {
		t.Fatalf("%s", got)
	}
}

func TestCatalogRejects(t *testing.T) {
	bad := []struct{ sw, k, v string }{
		{"sshd", "PermitRootLogin", "yes"}, {"sshd", "PasswordAuthentication", "yes"}, {"sshd", "ListenAddress", "0.0.0.0"},
		{"sshd", "MaxAuthTries", "99"}, {"nginx", "ssl_protocols", "TLSv1"}, {"nginx", "server_tokens", "off; }\nlocation / {"},
		{"tinyproxy", "Allow", "0.0.0.0/0"}, {"tinyproxy", "Allow", "10.0.0.1,"}, {"tinyproxy", "ConnectPort", "99999"},
		{"mysqld", "bind-address", "0.0.0.0"}, {"sshd", "PermitRootLogin", "no\nPermitEmptyPasswords yes"},
	}
	for _, b := range bad {
		if _, err := ValidateSetting(b.sw, b.k, b.v); err == nil {
			t.Errorf("accepted %+v", b)
		}
	}
	if k, err := ValidateSetting("sshd", "permitrootlogin", "no"); err != nil || k != "PermitRootLogin" {
		t.Fatal(k, err)
	}
}

func TestVerifyConfigCommands(t *testing.T) {
	g, _ := ParseGuard(nil)
	c := base()
	c.Action, c.Params = "set_config", Params{Software: "sshd", Key: "permitrootlogin", Value: "no"}
	pub, p, s := mk(t, c)
	got, err := Verify(pub, "srv", p, s, time.Now(), never, g)
	if err != nil || got.Params.Key != "PermitRootLogin" || got.Params.ConfirmSec != 120 {
		t.Fatalf("%+v %v", got, err)
	}
	c.Params.Value = "yes"
	pub, p, s = mk(t, c)
	if _, err := Verify(pub, "srv", p, s, time.Now(), never, g); err == nil {
		t.Fatal("unsafe value accepted")
	}
}

func TestExecuteConfigFlow(t *testing.T) {
	m, f, _ := newMgr(t)
	f.sshdT = func() string { return "permitrootlogin no\n" }
	var reported []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		reported = append(reported, r.URL.Path+" "+string(b))
	}))
	defer srv.Close()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	g, _ := ParseGuard(nil)
	a := &Agent{cfg: Config{PanelURL: srv.URL}, cm: m, guard: g, http: srv.Client(), pub: pub, st: state{ServerID: "srv"}, seen: map[string]time.Time{}}
	send := func(c Command) (string, string) {
		b, _ := json.Marshal(c)
		return a.Execute(string(b), base64.StdEncoding.EncodeToString(ed25519.Sign(priv, b)))
	}
	cmd := base()
	cmd.ID, cmd.Action, cmd.Params = "aaaaaaaaaaaaaaaaaaaaaaaa", "set_config", Params{Software: "sshd", Key: "PermitRootLogin", Value: "no"}
	if st, _ := send(cmd); st != "rejected" {
		t.Fatal("must be rejected while ALLOW_CONFIG_CHANGES is off")
	}
	a.cfg.AllowConfig = true
	cmd.Nonce = "n2"
	if st, out := send(cmd); st != "pending_confirm" {
		t.Fatalf("%s %s", st, out)
	}
	conf := base()
	conf.ID, conf.Nonce, conf.Action, conf.Params = "bbbbbbbbbbbbbbbbbbbbbbbb", "n3", "confirm_config", Params{ChangeID: "aaaaaaaaaaaaaaaaaaaaaaaa"}
	if st, _ := send(conf); st != "success" || len(reported) != 1 || !strings.Contains(reported[0], "/agent/commands/aaaaaaaaaaaaaaaaaaaaaaaa/result") || !strings.Contains(reported[0], "confirmed") {
		t.Fatalf("confirm: %v", reported)
	}
	conf.Nonce = "n4"
	if st, _ := send(conf); st != "failed" {
		t.Fatal("second confirm must fail")
	}
}
