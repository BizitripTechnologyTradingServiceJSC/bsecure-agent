package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

type Change struct{ Software, Key, Value string }

type planned struct {
	Path    string
	Old     string
	Existed bool
	New     string
}

type EditRec struct {
	Path    string `json:"path"`
	Existed bool   `json:"existed"`
	Old     string `json:"old"`
}

// Pending is an applied change that is reverted automatically unless a human confirms it in time.
type Pending struct {
	CmdID    string    `json:"cmdId"`
	Software string    `json:"software"`
	Key      string    `json:"key"`
	Value    string    `json:"value"`
	Deadline time.Time `json:"deadline"`
	Edits    []EditRec `json:"edits"`
	Failures int       `json:"failures,omitempty"`
}

// RevertFailed records a failed auto-revert and postpones the next attempt (1m, 2m, 4m ... max 1h).
func (m *ConfigManager) RevertFailed(p Pending) int {
	ps := m.load()
	for i := range ps {
		if ps[i].CmdID == p.CmdID {
			ps[i].Failures++
			backoff := time.Minute << min(ps[i].Failures-1, 6)
			if backoff > time.Hour {
				backoff = time.Hour
			}
			ps[i].Deadline = m.Now().Add(backoff)
			_ = m.save(ps)
			return ps[i].Failures
		}
	}
	return 0
}

// ConfigManager edits a small, fixed set of config files with backup, validation, verification and auto-rollback.
// Root prefixes all absolute paths (empty in production, a temp dir in tests).
type ConfigManager struct {
	Root     string
	Run      Runner
	StateDir string
	Now      func() time.Time
	Sleep    func(time.Duration)
}

func NewConfigManager(stateDir string) *ConfigManager {
	return &ConfigManager{Run: ExecRunner, StateDir: stateDir, Now: time.Now, Sleep: time.Sleep}
}

func (m *ConfigManager) abs(p string) string { return filepath.Join(m.Root, p) }
func (m *ConfigManager) read(p string) (string, bool) {
	b, err := os.ReadFile(m.abs(p))
	return string(b), err == nil
}

func (m *ConfigManager) write(p, content string) error {
	dst := m.abs(p)
	mode := os.FileMode(0o644)
	if st, err := os.Stat(dst); err == nil {
		mode = st.Mode().Perm()
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(dst), ".bsecure-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString(content); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), dst)
}

func (m *ConfigManager) glob(patterns ...string) []string {
	var out []string
	for _, pat := range patterns {
		ms, _ := filepath.Glob(m.abs(pat))
		for _, f := range ms {
			out = append(out, strings.TrimPrefix(f, m.Root))
		}
	}
	return out
}

// ---- planning: compute new file contents without touching disk ----

func (m *ConfigManager) Plan(c Change) ([]planned, error) {
	switch c.Software {
	case "sshd":
		return m.planSSHD(c)
	case "nginx":
		return m.planNginx(c)
	case "tinyproxy":
		return m.planTinyproxy(c)
	}
	return nil, fmt.Errorf("unsupported software %q", c.Software)
}

const sshdDropIn = "/etc/ssh/sshd_config.d/00-bsecure.conf"
const header = "# Managed by bsecure-agent. Manual edits to these lines may be overwritten.\n"

var sshInclude = regexp.MustCompile(`(?im)^\s*Include\s+\S*sshd_config\.d`)

func (m *ConfigManager) planSSHD(c Change) ([]planned, error) {
	main, ok := m.read("/etc/ssh/sshd_config")
	if !ok {
		return nil, errors.New("/etc/ssh/sshd_config not found")
	}
	if !sshInclude.MatchString(main) {
		return nil, errors.New("sshd_config has no Include for sshd_config.d; refusing to guess where to write")
	}
	old, existed := m.read(sshdDropIn)
	var lines []string
	for _, l := range strings.Split(old, "\n") {
		t := strings.TrimSpace(l)
		if t == "" || strings.HasPrefix(t, "#") || strings.EqualFold(strings.Fields(t)[0], c.Key) {
			continue
		}
		lines = append(lines, t)
	}
	lines = append(lines, c.Key+" "+c.Value)
	return []planned{{Path: sshdDropIn, Old: old, Existed: existed, New: header + strings.Join(lines, "\n") + "\n"}}, nil
}

// replaceDirective rewrites every `key ...;` directive in the code part of each line (comments are left alone).
func replaceDirective(text, key, value string) (string, bool) {
	re := regexp.MustCompile(`(^|[\s{};])` + regexp.QuoteMeta(key) + `[ \t]+[^;{}\n]*;`)
	hit := false
	lines := strings.Split(text, "\n")
	for i, l := range lines {
		code, comment := l, ""
		if j := strings.Index(l, "#"); j >= 0 {
			code, comment = l[:j], l[j:]
		}
		if re.MatchString(code) {
			hit = true
			lines[i] = re.ReplaceAllString(code, "${1}"+key+" "+value+";") + comment
		}
	}
	return strings.Join(lines, "\n"), hit
}

const nginxDropIn = "/etc/nginx/conf.d/00-bsecure.conf"

func (m *ConfigManager) planNginx(c Change) ([]planned, error) {
	var out []planned
	found := false
	for _, f := range m.glob("/etc/nginx/nginx.conf", "/etc/nginx/conf.d/*.conf", "/etc/nginx/sites-enabled/*") {
		old, _ := m.read(f)
		nw, hit := replaceDirective(old, c.Key, c.Value)
		if !hit {
			continue
		}
		found = true
		if nw != old {
			out = append(out, planned{Path: f, Old: old, Existed: true, New: nw})
		}
	}
	if !found {
		old, existed := m.read(nginxDropIn)
		if _, ok := m.read("/etc/nginx/nginx.conf"); !ok {
			return nil, errors.New("/etc/nginx/nginx.conf not found")
		}
		out = append(out, planned{Path: nginxDropIn, Old: old, Existed: existed, New: old + header + c.Key + " " + c.Value + ";\n"})
	}
	return out, nil
}

func (m *ConfigManager) planTinyproxy(c Change) ([]planned, error) {
	var path string
	for _, p := range []string{"/etc/tinyproxy/tinyproxy.conf", "/etc/tinyproxy.conf"} {
		if _, ok := m.read(p); ok {
			path = p
			break
		}
	}
	if path == "" {
		return nil, errors.New("tinyproxy config not found")
	}
	old, _ := m.read(path)
	re := regexp.MustCompile(`(?i)^\s*` + regexp.QuoteMeta(c.Key) + `\s`)
	var keep []string
	for _, l := range strings.Split(strings.TrimRight(old, "\n"), "\n") {
		if !re.MatchString(l) {
			keep = append(keep, l)
		}
	}
	if strings.EqualFold(c.Key, "Allow") || strings.EqualFold(c.Key, "ConnectPort") {
		for _, v := range strings.Split(c.Value, ",") {
			keep = append(keep, c.Key+" "+strings.TrimSpace(v))
		}
	} else {
		keep = append(keep, c.Key+" "+c.Value)
	}
	return []planned{{Path: path, Old: old, Existed: true, New: strings.Join(keep, "\n") + "\n"}}, nil
}

// Describe summarises line-level differences (used in results shown to the approver).
func Describe(ps []planned) string {
	var b strings.Builder
	for _, p := range ps {
		fmt.Fprintf(&b, "%s:\n", p.Path)
		oldL, newL := map[string]bool{}, map[string]bool{}
		for _, l := range strings.Split(p.Old, "\n") {
			oldL[l] = true
		}
		for _, l := range strings.Split(p.New, "\n") {
			newL[l] = true
		}
		n := 0
		for _, l := range strings.Split(p.Old, "\n") {
			if !newL[l] && strings.TrimSpace(l) != "" && n < 10 {
				fmt.Fprintf(&b, "- %s\n", strings.TrimSpace(l))
				n++
			}
		}
		for _, l := range strings.Split(p.New, "\n") {
			if !oldL[l] && strings.TrimSpace(l) != "" && n < 20 {
				fmt.Fprintf(&b, "+ %s\n", strings.TrimSpace(l))
				n++
			}
		}
	}
	return b.String()
}

// ---- lockout guard ----

func (m *ConfigManager) hasKeys(includeRoot bool) bool {
	pats := []string{"/home/*/.ssh/authorized_keys"}
	if includeRoot {
		pats = append(pats, "/root/.ssh/authorized_keys")
	}
	for _, f := range m.glob(pats...) {
		b, _ := m.read(f)
		for _, l := range strings.Split(b, "\n") {
			if t := strings.TrimSpace(l); t != "" && !strings.HasPrefix(t, "#") {
				return true
			}
		}
	}
	return false
}

func (m *ConfigManager) guard(c Change) error {
	if c.Software != "sshd" {
		return nil
	}
	switch {
	case c.Key == "PasswordAuthentication" && !m.hasKeys(true):
		return errors.New("refusing: no authorized_keys found for any user, disabling password login would lock everyone out")
	case c.Key == "PermitRootLogin" && c.Value == "no" && !m.hasKeys(false):
		return errors.New("refusing: no non-root user has authorized_keys, PermitRootLogin no could lock you out")
	case c.Key == "PermitRootLogin" && !m.hasKeys(true):
		return errors.New("refusing: no authorized_keys found, root key-only login would lock you out")
	}
	return nil
}

// ---- apply / confirm / revert ----

func (m *ConfigManager) validate(sw string) error {
	var name string
	switch sw {
	case "sshd":
		name = "sshd"
	case "nginx":
		name = "nginx"
	default:
		return nil
	}
	flag := "-t"
	if out, err := m.Run("", name, flag); err != nil {
		return fmt.Errorf("%s %s failed: %s", name, flag, trunc(out))
	}
	return nil
}

func (m *ConfigManager) reload(sw string) error {
	units := map[string][]string{"sshd": {"ssh", "sshd"}, "nginx": {"nginx"}, "tinyproxy": {"tinyproxy"}}[sw]
	verb := "reload-or-restart"
	if sw == "tinyproxy" {
		verb = "restart"
	}
	var last string
	for _, u := range units {
		out, err := m.Run("", "systemctl", verb, u)
		if err == nil {
			return nil
		}
		last = out
		if noSystemd(out, err) {
			return m.reloadWithoutSystemd(sw)
		}
	}
	return fmt.Errorf("systemctl %s failed: %s", verb, trunc(last))
}

func noSystemd(out string, err error) bool {
	s := out + " " + err.Error()
	return strings.Contains(s, "executable file not found") || strings.Contains(s, "not been booted with systemd") ||
		strings.Contains(s, "Failed to connect to bus")
}

// reloadWithoutSystemd covers containers and OpenRC/sysvinit hosts. Signals go to the master process from
// its pid file only (pkill would also hit per-session sshd children).
func (m *ConfigManager) reloadWithoutSystemd(sw string) error {
	if sw == "nginx" {
		if out, err := m.Run("", "nginx", "-s", "reload"); err != nil {
			return fmt.Errorf("nginx -s reload failed: %s", trunc(out))
		}
		return nil
	}
	pidFiles := map[string][]string{
		"sshd":      {"/run/sshd.pid", "/var/run/sshd.pid"},
		"tinyproxy": {"/run/tinyproxy/tinyproxy.pid", "/var/run/tinyproxy/tinyproxy.pid", "/run/tinyproxy.pid"},
	}[sw]
	sig := map[string]string{"sshd": "-HUP", "tinyproxy": "-USR1"}[sw] // tinyproxy re-reads its config on USR1
	for _, f := range pidFiles {
		b, ok := m.read(f)
		pid := strings.TrimSpace(b)
		if !ok || !regexp.MustCompile(`^[1-9][0-9]*$`).MatchString(pid) {
			continue
		}
		if out, err := m.Run("", "kill", sig, pid); err != nil {
			return fmt.Errorf("kill %s %s failed: %s", sig, pid, trunc(out))
		}
		return nil
	}
	return fmt.Errorf("no systemd and no pid file found for %s", sw)
}

func (m *ConfigManager) verify(c Change) error {
	col := &Collector{Root: m.Root, Run: m.Run}
	switch c.Software {
	case "sshd":
		out, err := m.Run("", "sshd", "-T")
		if err != nil {
			return fmt.Errorf("sshd -T failed: %s", trunc(out))
		}
		if got := ParseSSHD(out)[strings.ToLower(c.Key)]; fmt.Sprint(got) != strings.ToLower(c.Value) {
			return fmt.Errorf("effective %s is %v, not %s (overridden elsewhere?)", c.Key, got, c.Value)
		}
	case "nginx":
		sw := col.nginx(map[string]bool{"nginx": true})
		if sw == nil {
			return errors.New("cannot re-read nginx config")
		}
		switch c.Key {
		case "server_tokens":
			if sw.Settings["server_tokens"] != c.Value {
				return fmt.Errorf("server_tokens is %v after change", sw.Settings["server_tokens"])
			}
		case "ssl_protocols":
			if strings.Join(sw.Settings["ssl_protocols"].([]string), " ") != sortedFields(c.Value) {
				return fmt.Errorf("ssl_protocols is %v after change", sw.Settings["ssl_protocols"])
			}
		}
	case "tinyproxy":
		for i := 0; i < 6; i++ {
			for _, name := range col.processes() {
				if name == "tinyproxy" {
					return nil
				}
			}
			m.Sleep(500 * time.Millisecond)
		}
		return errors.New("tinyproxy is not running after restart")
	}
	return nil
}

func sortedFields(s string) string {
	f := strings.Fields(s)
	for i := range f {
		for j := i + 1; j < len(f); j++ {
			if f[j] < f[i] {
				f[i], f[j] = f[j], f[i]
			}
		}
	}
	return strings.Join(f, " ")
}

func (m *ConfigManager) restore(ps []EditRec) error {
	var firstErr error
	for _, e := range ps {
		var err error
		if e.Existed {
			err = m.write(e.Path, e.Old)
		} else if err = os.Remove(m.abs(e.Path)); os.IsNotExist(err) {
			err = nil
		}
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func recs(ps []planned) []EditRec {
	var out []EditRec
	for _, p := range ps {
		out = append(out, EditRec{Path: p.Path, Existed: p.Existed, Old: p.Old})
	}
	return out
}

// Apply returns a result status (success|dry_run|failed|pending_confirm) and an output message.
func (m *ConfigManager) Apply(cmdID string, c Change, confirmSec int, dry bool) (string, string) {
	for _, p := range m.load() {
		if p.Software == c.Software {
			return "failed", fmt.Sprintf("change %s for %s is still awaiting confirmation", p.CmdID, c.Software)
		}
	}
	if err := m.guard(c); err != nil {
		return "failed", err.Error()
	}
	plans, err := m.Plan(c)
	if err != nil {
		return "failed", err.Error()
	}
	var changed []planned
	for _, p := range plans {
		if p.New != p.Old {
			changed = append(changed, p)
		}
	}
	if len(changed) == 0 {
		return "success", "already configured, nothing to change"
	}
	desc := Describe(changed)
	if dry {
		return "dry_run", "DRY-RUN would change:\n" + desc
	}
	rec := recs(changed)
	fail := func(stage string, err error) (string, string) {
		msg := fmt.Sprintf("%s: %v", stage, err)
		if rerr := m.restore(rec); rerr != nil {
			msg += fmt.Sprintf(" (RESTORE FAILED: %v)", rerr)
		} else {
			msg += " (original config restored)"
			if stage != "validate" {
				_ = m.reload(c.Software)
			}
		}
		return "failed", trunc(msg)
	}
	for _, p := range changed {
		if err := m.write(p.Path, p.New); err != nil {
			return fail("write", err)
		}
	}
	if err := m.validate(c.Software); err != nil {
		return fail("validate", err)
	}
	if err := m.reload(c.Software); err != nil {
		return fail("reload", err)
	}
	if err := m.verify(c); err != nil {
		return fail("verify", err)
	}
	deadline := m.Now().Add(time.Duration(confirmSec) * time.Second)
	if err := m.save(append(m.load(), Pending{CmdID: cmdID, Software: c.Software, Key: c.Key, Value: c.Value, Deadline: deadline, Edits: rec})); err != nil {
		return fail("persist", err)
	}
	return "pending_confirm", trunc(fmt.Sprintf("applied; will auto-revert at %s unless confirmed\n%s", deadline.UTC().Format(time.RFC3339), desc))
}

// Confirm cancels the auto-revert for a change. Returns false if nothing was pending.
func (m *ConfigManager) Confirm(cmdID string) bool {
	var keep []Pending
	found := false
	for _, p := range m.load() {
		if p.CmdID == cmdID {
			found = true
			continue
		}
		keep = append(keep, p)
	}
	if found {
		_ = m.save(keep)
	}
	return found
}

// Due returns pending changes whose confirmation window has passed.
func (m *ConfigManager) Due() []Pending {
	var out []Pending
	for _, p := range m.load() {
		if !m.Now().Before(p.Deadline) {
			out = append(out, p)
		}
	}
	return out
}

// Revert restores the original files and reloads the service, then forgets the pending entry.
func (m *ConfigManager) Revert(p Pending) error {
	err := m.restore(p.Edits)
	if err == nil {
		if rerr := m.reload(p.Software); rerr != nil {
			err = rerr
		}
	}
	if err == nil {
		m.Confirm(p.CmdID) // removes from pending
	}
	return err
}

func (m *ConfigManager) statePath() string { return filepath.Join(m.StateDir, "pending.json") }

func (m *ConfigManager) load() []Pending {
	b, err := os.ReadFile(m.statePath())
	if err != nil {
		return nil
	}
	var ps []Pending
	_ = json.Unmarshal(b, &ps)
	return ps
}

func (m *ConfigManager) save(ps []Pending) error {
	if err := os.MkdirAll(m.StateDir, 0o700); err != nil {
		return err
	}
	b, _ := json.Marshal(ps)
	return os.WriteFile(m.statePath(), b, 0o600) // contains old config contents: root only
}
