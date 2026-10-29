package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Everything here is read-only: the agent reports facts, the Control Panel decides what they mean.

type Port struct {
	Proto   string `json:"proto"`
	Addr    string `json:"addr"`
	Port    int    `json:"port"`
	PID     int    `json:"pid,omitempty"`
	Process string `json:"process,omitempty"`
}

type Software struct {
	Name       string         `json:"name"`
	Version    string         `json:"version,omitempty"`
	Running    bool           `json:"running"`
	ConfigPath string         `json:"configPath,omitempty"`
	ConfigHash string         `json:"configHash,omitempty"` // full config is never sent: it may hold secrets
	Settings   map[string]any `json:"settings,omitempty"`
	Error      string         `json:"error,omitempty"`
}

type Inventory struct {
	CollectedAt string     `json:"collectedAt"`
	Hostname    string     `json:"hostname"`
	OS          string     `json:"os"`
	Kernel      string     `json:"kernel"`
	Ports       []Port     `json:"ports"`
	Software    []Software `json:"software"`
}

// Collector reads from Root+"/proc" and Root+"/etc" (Root is "" in production; tests use a temp dir).
type Collector struct {
	Root string
	Run  Runner
}

func (c *Collector) p(path string) string { return filepath.Join(c.Root, path) }

func (c *Collector) Collect() Inventory {
	host, _ := os.Hostname()
	procs := c.processes()
	inv := Inventory{Software: []Software{}, CollectedAt: time.Now().UTC().Format(time.RFC3339), Hostname: host, OS: c.osName(), Kernel: c.readTrim("/proc/sys/kernel/osrelease")}
	inv.Ports = c.ListeningPorts()
	running := map[string]bool{}
	for _, n := range procs {
		running[n] = true
	}
	for _, s := range []func(map[string]bool) *Software{c.sshd, c.nginx, c.tinyproxy} {
		if sw := s(running); sw != nil {
			inv.Software = append(inv.Software, *sw)
		}
	}
	return inv
}

func (c *Collector) readTrim(path string) string {
	b, err := os.ReadFile(c.p(path))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func (c *Collector) osName() string {
	for _, l := range strings.Split(c.readTrim("/etc/os-release"), "\n") {
		if v, ok := strings.CutPrefix(l, "PRETTY_NAME="); ok {
			return strings.Trim(v, `"`)
		}
	}
	return ""
}

// processes returns the comm of every running process.
func (c *Collector) processes() map[int]string {
	out := map[int]string{}
	ents, _ := os.ReadDir(c.p("/proc"))
	for _, e := range ents {
		if pid, err := strconv.Atoi(e.Name()); err == nil {
			if b, err := os.ReadFile(c.p("/proc/" + e.Name() + "/comm")); err == nil {
				out[pid] = strings.TrimSpace(string(b))
			}
		}
	}
	return out
}

func (c *Collector) socketOwners() map[string]int {
	owners := map[string]int{}
	fds, _ := filepath.Glob(c.p("/proc/[0-9]*/fd/*"))
	for _, fd := range fds {
		l, err := os.Readlink(fd)
		if err != nil || !strings.HasPrefix(l, "socket:[") {
			continue
		}
		parts := strings.Split(strings.TrimPrefix(fd, c.Root), "/")
		if pid, err := strconv.Atoi(parts[2]); err == nil {
			owners[strings.TrimSuffix(strings.TrimPrefix(l, "socket:["), "]")] = pid
		}
	}
	return owners
}

func (c *Collector) ListeningPorts() []Port {
	owners, procs := c.socketOwners(), c.processes()
	ports := []Port{}
	for _, f := range []struct{ file, proto, state string }{
		{"/proc/net/tcp", "tcp", "0A"}, {"/proc/net/tcp6", "tcp6", "0A"}, {"/proc/net/udp", "udp", "07"}, {"/proc/net/udp6", "udp6", "07"},
	} {
		b, err := os.ReadFile(c.p(f.file))
		if err != nil {
			continue
		}
		for _, p := range ParseProcNet(string(b), f.proto, f.state) {
			if inode := p.inode; inode != "" {
				if pid, ok := owners[inode]; ok {
					p.PID, p.Process = pid, procs[pid]
				}
			}
			ports = append(ports, p.Port)
		}
	}
	sort.Slice(ports, func(i, j int) bool { return ports[i].Port < ports[j].Port })
	return ports
}

type procPort struct {
	Port
	inode string
}

// ParseProcNet parses /proc/net/{tcp,udp}[6] keeping only sockets in the given state.
func ParseProcNet(data, proto, state string) []struct {
	Port
	inode string
} {
	var out []struct {
		Port
		inode string
	}
	for i, l := range strings.Split(data, "\n") {
		f := strings.Fields(l)
		if i == 0 || len(f) < 10 || f[3] != state {
			continue
		}
		addr, port, ok := parseHexAddr(f[1])
		if !ok {
			continue
		}
		out = append(out, struct {
			Port
			inode string
		}{Port{Proto: proto, Addr: addr, Port: port}, f[9]})
	}
	return out
}

func parseHexAddr(s string) (string, int, bool) {
	a, p, ok := strings.Cut(s, ":")
	if !ok {
		return "", 0, false
	}
	port, err := strconv.ParseInt(p, 16, 32)
	raw, err2 := hex.DecodeString(a)
	if err != nil || err2 != nil || (len(raw) != 4 && len(raw) != 16) {
		return "", 0, false
	}
	ip := make(net.IP, len(raw))
	for i := 0; i < len(raw); i += 4 { // each 32-bit word is little-endian
		ip[i], ip[i+1], ip[i+2], ip[i+3] = raw[i+3], raw[i+2], raw[i+1], raw[i]
	}
	return ip.String(), int(port), true
}

var verRe = regexp.MustCompile(`\d+(?:\.\d+)+\w*`)

func (c *Collector) version(name string, args ...string) string {
	if c.Run == nil {
		return ""
	}
	out, _ := c.Run("", name, args...)
	return verRe.FindString(out)
}

func hashFiles(files []string, data []string) string {
	h := sha256.New()
	for i := range files {
		h.Write([]byte(files[i]))
		h.Write([]byte(data[i]))
	}
	return hex.EncodeToString(h.Sum(nil))
}

func (c *Collector) readAll(patterns ...string) (files, data []string) {
	for _, pat := range patterns {
		m, _ := filepath.Glob(c.p(pat))
		for _, f := range m {
			if b, err := os.ReadFile(f); err == nil {
				files, data = append(files, strings.TrimPrefix(f, c.Root)), append(data, string(b))
			}
		}
	}
	return
}

func hasProc(running map[string]bool, names ...string) bool {
	for _, n := range names {
		if running[n] {
			return true
		}
	}
	return false
}

// ---- sshd ----

var sshKeys = map[string]bool{"permitrootlogin": true, "passwordauthentication": true, "permitemptypasswords": true, "x11forwarding": true,
	"maxauthtries": true, "port": true, "pubkeyauthentication": true, "kbdinteractiveauthentication": true, "challengeresponseauthentication": true,
	"allowtcpforwarding": true, "logingracetime": true, "protocol": true}

// ParseSSHD follows sshd rules: first occurrence of a keyword wins, parsing stops at the first Match block.
func ParseSSHD(text string) map[string]any {
	s := map[string]any{}
	var ports []string
	for _, l := range strings.Split(text, "\n") {
		f := strings.Fields(strings.TrimSpace(l))
		if len(f) < 2 || strings.HasPrefix(f[0], "#") {
			continue
		}
		k := strings.ToLower(f[0])
		if k == "match" {
			break
		}
		if k == "port" {
			ports = append(ports, f[1])
		} else if _, seen := s[k]; !seen && sshKeys[k] {
			s[k] = strings.ToLower(f[1])
		}
	}
	if len(ports) > 0 {
		s["port"] = ports
	}
	return s
}

func (c *Collector) sshd(running map[string]bool) *Software {
	files, data := c.readAll("/etc/ssh/sshd_config", "/etc/ssh/sshd_config.d/*.conf")
	run := hasProc(running, "sshd")
	if len(files) == 0 && !run {
		return nil
	}
	sw := &Software{Name: "sshd", Running: run, ConfigPath: "/etc/ssh/sshd_config", Version: c.version("ssh", "-V")}
	if c.Run != nil { // effective config (includes defaults and includes); needs root
		if out, err := c.Run("", "sshd", "-T"); err == nil {
			sw.Settings = ParseSSHD(out)
		}
	}
	if sw.Settings == nil {
		// drop-ins are read first by sshd (Include at top), so order: .d files then main
		sort.SliceStable(files, func(i, j int) bool { return strings.Contains(files[i], ".d/") && !strings.Contains(files[j], ".d/") })
		sw.Settings = ParseSSHD(strings.Join(data, "\n"))
	}
	sw.ConfigHash = hashFiles(files, data)
	return sw
}

// ---- nginx ----

var commentRe = regexp.MustCompile(`(?m)#.*$`)

func ParseNginx(text string) map[string]any {
	text = commentRe.ReplaceAllString(text, "")
	s := map[string]any{"server_tokens": "", "autoindex_on": 0, "limit_req": false, "hsts": false, "listen_ssl": 0}
	protos := map[string]bool{}
	for _, m := range regexp.MustCompile(`\bserver_tokens\s+(\w+)\s*;`).FindAllStringSubmatch(text, -1) {
		s["server_tokens"] = strings.ToLower(m[1])
	}
	for _, m := range regexp.MustCompile(`\bssl_protocols\s+([^;]+);`).FindAllStringSubmatch(text, -1) {
		for _, p := range strings.Fields(m[1]) {
			protos[p] = true
		}
	}
	s["autoindex_on"] = len(regexp.MustCompile(`\bautoindex\s+on\s*;`).FindAllString(text, -1))
	s["limit_req"] = regexp.MustCompile(`\blimit_req(_zone)?\s`).MatchString(text)
	s["hsts"] = strings.Contains(strings.ToLower(text), "strict-transport-security")
	s["listen_ssl"] = len(regexp.MustCompile(`\blisten\s[^;]*\bssl\b`).FindAllString(text, -1))
	var pl []string
	for p := range protos {
		pl = append(pl, p)
	}
	sort.Strings(pl)
	s["ssl_protocols"] = pl
	return s
}

func (c *Collector) nginx(running map[string]bool) *Software {
	files, data := c.readAll("/etc/nginx/nginx.conf", "/etc/nginx/conf.d/*.conf", "/etc/nginx/sites-enabled/*")
	run := hasProc(running, "nginx")
	if len(files) == 0 && !run {
		return nil
	}
	return &Software{Name: "nginx", Running: run, ConfigPath: "/etc/nginx/nginx.conf", Version: c.version("nginx", "-v"),
		Settings: ParseNginx(strings.Join(data, "\n")), ConfigHash: hashFiles(files, data)}
}

// ---- tinyproxy ----

func ParseTinyproxy(text string) map[string]any {
	s := map[string]any{"allow": []string{}, "connectport": []string{}, "basicauth": false}
	for _, l := range strings.Split(text, "\n") {
		f := strings.Fields(strings.TrimSpace(l))
		if len(f) < 2 || strings.HasPrefix(f[0], "#") {
			continue
		}
		switch strings.ToLower(f[0]) {
		case "allow":
			s["allow"] = append(s["allow"].([]string), f[1])
		case "connectport":
			s["connectport"] = append(s["connectport"].([]string), f[1])
		case "basicauth":
			s["basicauth"] = true // credentials are never reported
		case "listen", "port", "bind", "disableviaheader", "loglevel":
			s[strings.ToLower(f[0])] = f[1]
		}
	}
	return s
}

func (c *Collector) tinyproxy(running map[string]bool) *Software {
	files, data := c.readAll("/etc/tinyproxy/tinyproxy.conf", "/etc/tinyproxy.conf")
	run := hasProc(running, "tinyproxy")
	if len(files) == 0 && !run {
		return nil
	}
	sw := &Software{Name: "tinyproxy", Running: run, Version: c.version("tinyproxy", "-v")}
	if len(files) > 0 {
		sw.ConfigPath, sw.Settings, sw.ConfigHash = files[0], ParseTinyproxy(strings.Join(data, "\n")), hashFiles(files, data)
	} else {
		sw.Error = "config not found"
	}
	return sw
}
