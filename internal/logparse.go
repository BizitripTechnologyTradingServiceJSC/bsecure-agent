package agent

import (
	"bytes"
	"net/netip"
	"regexp"
	"strings"
	"time"
)

// Parser turns one log line into a normalised, redacted event (nil = not interesting).
type Parser func(line string, now time.Time) *Event

var (
	nginxRe = regexp.MustCompile(`^(\S+) \S+ \S+ \[[^\]]+\] "(\S+) (\S+)[^"]*" (\d{3}) `)
	// Typical scanner / exploit probes. Matching is on the request path only.
	scanRe = regexp.MustCompile(`(?i)(/\.env|/\.git/|wp-login\.php|xmlrpc\.php|phpmyadmin|/vendor/phpunit|/cgi-bin/|/actuator|/boaform|/\.aws|/etc/passwd|\.\./|%2e%2e|union(%20|\+)select|<script|%3cscript|/shell\.php|/eval-stdin\.php)`)

	sudoRe    = regexp.MustCompile(`sudo(?:\[\d+\])?:.*(?:authentication failure|incorrect password attempts)`)
	oomRe     = regexp.MustCompile(`Out of memory: Killed process`)
	useraddRe = regexp.MustCompile(`useradd\[\d+\]: new user`)
	segvRe    = regexp.MustCompile(`segfault at`)
	secretRe  = regexp.MustCompile(`(?i)(password|passwd|token|secret|key)=\S+`)
)

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// ParseNginxAccess flags probes and auth failures. Query strings and user agents are dropped
// (they can carry secrets or attacker-written prompt-injection text).
func ParseNginxAccess(line string, now time.Time) *Event {
	m := nginxRe.FindStringSubmatch(line)
	if m == nil {
		return nil
	}
	addr, err := netip.ParseAddr(m[1])
	if err != nil {
		return nil
	}
	path, _, _ := strings.Cut(m[3], "?")
	typ := ""
	switch {
	case scanRe.MatchString(m[3]):
		typ = "web_scan"
	case m[4] == "401":
		typ = "web_auth_failed"
	default:
		return nil
	}
	return &Event{TS: now.UTC().Format(time.RFC3339), Source: "nginx", Type: typ, IP: addr.Unmap().String(),
		Line: clip(m[1]+" "+m[2]+" "+path+" "+m[4], 300)}
}

func ParseSyslog(line string, now time.Time) *Event {
	typ := ""
	switch {
	case sudoRe.MatchString(line):
		typ = "sudo_failed"
	case oomRe.MatchString(line):
		typ = "oom_kill"
	case useraddRe.MatchString(line):
		typ = "user_added"
	case segvRe.MatchString(line):
		typ = "segfault"
	default:
		return nil
	}
	return &Event{TS: now.UTC().Format(time.RFC3339), Source: "syslog", Type: typ, Line: clip(secretRe.ReplaceAllString(line, "$1=<redacted>"), 300)}
}

// The quick* functions are allocation-free filters run on every raw log line before the (much slower) parsers.
// They may let uninteresting lines through, but must never reject a line its parser would accept; tests check that.
var (
	sshNeedles    = [][]byte{[]byte("Failed "), []byte("Invalid user"), []byte("[preauth]")}
	syslogNeedles = [][]byte{[]byte("sudo"), []byte("Out of memory"), []byte("useradd"), []byte("segfault")}
	nginxNeedles  = [][]byte{[]byte("/.env"), []byte("/.git/"), []byte("wp-login.php"), []byte("xmlrpc.php"), []byte("phpmyadmin"), []byte("/vendor/phpunit"),
		[]byte("/cgi-bin/"), []byte("/actuator"), []byte("/boaform"), []byte("/.aws"), []byte("/etc/passwd"), []byte("../"), []byte("%2e%2e"),
		[]byte("union%20select"), []byte("union+select"), []byte("<script"), []byte("%3cscript"), []byte("/shell.php"), []byte("/eval-stdin.php")}
	nginx401 = []byte(`" 401 `)
)

func anyContains(b []byte, needles [][]byte) bool {
	for _, n := range needles {
		if bytes.Contains(b, n) {
			return true
		}
	}
	return false
}

func quickSSH(b []byte) bool    { return anyContains(b, sshNeedles) }
func quickSyslog(b []byte) bool { return anyContains(b, syslogNeedles) }

// nginxQuick looks only at the request ("GET /path HTTP/1.1"), which is all the scanner patterns match on, and
// lowercases that short span into a scratch buffer because the patterns are case-insensitive.
type nginxQuick struct{ buf []byte }

func (q *nginxQuick) Match(b []byte) bool {
	i := bytes.IndexByte(b, '"')
	if i < 0 {
		return false
	}
	j := bytes.IndexByte(b[i+1:], '"')
	if j < 0 {
		return false
	}
	req := b[i+1 : i+1+j]
	if bytes.HasPrefix(b[i+1+j:], nginx401) {
		return true
	}
	q.buf = append(q.buf[:0], req...)
	for k, c := range q.buf {
		if c >= 'A' && c <= 'Z' {
			q.buf[k] = c + 32
		}
	}
	return anyContains(q.buf, nginxNeedles)
}
