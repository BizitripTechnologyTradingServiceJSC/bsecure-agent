package agent

import (
	"bufio"
	"io"
	"net/netip"
	"os"
	"regexp"
	"time"
)

type Event struct {
	TS     string `json:"ts"`
	Source string `json:"source"`
	Type   string `json:"type"`
	IP     string `json:"ip,omitempty"`
	User   string `json:"user,omitempty"`
	Line   string `json:"line"`
}

var (
	// group 1 user, 2 ip, 3 port
	reFailed  = regexp.MustCompile(`Failed (?:password|publickey|keyboard-interactive/pam) for (?:invalid user )?(\S+) from (\S+) port (\d+)`)
	reInvalid = regexp.MustCompile(`Invalid user (\S*) from (\S+)(?: port (\d+))?`) // older sshd omits the port
	rePreauth = regexp.MustCompile(`(?:Connection closed by|Disconnected from) (?:authenticating|invalid) user (\S*) (\S+) port (\d+) \[preauth\]`)
)

// SSHParser counts authentication attempts, not log lines. sshd writes several lines per connection
// ("Invalid user", then one "Failed password" per try, then "Connection closed ... [preauth]"):
// every failed try counts once; the other lines count only for a connection that made no failed try
// (e.g. key-only scanners), so one bad login is no longer counted twice.
type SSHParser struct {
	conns map[string]*sshConn
	calls int
}

type sshConn struct {
	placeholder bool // an Invalid/preauth line was counted and will absorb the next failed try
	counted     bool // at least one event was emitted for this connection
	seen        time.Time
}

func NewSSHParser() *SSHParser { return &SSHParser{conns: map[string]*sshConn{}} }

// ParseSSH parses a single line without connection context (kept for callers that need a pure function).
func ParseSSH(line string, now time.Time) *Event { return NewSSHParser().Parse(line, now) }

func (p *SSHParser) Parse(line string, now time.Time) *Event {
	if p.calls++; p.calls%1000 == 0 {
		for k, c := range p.conns {
			if now.Sub(c.seen) > 10*time.Minute {
				delete(p.conns, k)
			}
		}
	}
	for i, re := range []*regexp.Regexp{reFailed, reInvalid, rePreauth} {
		m := re.FindStringSubmatchIndex(line)
		if m == nil {
			continue
		}
		key := line[m[4]:m[5]]
		if m[6] >= 0 {
			key += "|" + line[m[6]:m[7]]
		}
		c := p.conns[key]
		if c == nil {
			c = &sshConn{}
			p.conns[key] = c
		}
		c.seen = now
		if i == 0 { // a real failed attempt
			if c.placeholder {
				c.placeholder = false // already counted by the earlier Invalid line
				return nil
			}
		} else { // Invalid user / preauth close: only the first line of a connection counts
			if c.placeholder || c.counted {
				return nil
			}
			c.placeholder = true
		}
		c.counted = true
		user, ip := line[m[2]:m[3]], line[m[4]:m[5]]
		addr, err := netip.ParseAddr(ip)
		if err != nil {
			return nil
		}
		redacted := line[:m[2]] + "<user>" + line[m[3]:]
		if len(redacted) > 400 {
			redacted = redacted[:400]
		}
		if len(user) > 64 {
			user = user[:64]
		}
		return &Event{TS: now.UTC().Format(time.RFC3339), Source: "sshd", Type: "ssh_auth_failed", IP: addr.Unmap().String(), User: user, Line: redacted}
	}
	return nil
}

// Tail polls a file from its current end, handling truncation and rotation (rename + new file).
type Tail struct {
	Path   string
	offset int64
	init   bool
	file   os.FileInfo // identity of the file the offset belongs to
}

func (t *Tail) Read(max int) ([]string, error) {
	f, err := os.Open(t.Path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !t.init {
		t.offset, t.init, t.file = st.Size(), true, st
		return nil, nil
	}
	// A rotated-in file can already be larger than our old offset, so size alone cannot detect rotation.
	if !os.SameFile(t.file, st) || st.Size() < t.offset {
		t.offset = 0
	}
	t.file = st
	if _, err := f.Seek(t.offset, io.SeekStart); err != nil {
		return nil, err
	}
	var lines []string
	r := bufio.NewReader(f)
	for len(lines) < max {
		s, err := r.ReadString('\n')
		if err != nil {
			break // partial last line stays for next poll
		}
		t.offset += int64(len(s))
		lines = append(lines, s[:len(s)-1])
	}
	return lines, nil
}
