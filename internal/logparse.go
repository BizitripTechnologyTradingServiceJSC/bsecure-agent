package agent

import (
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
