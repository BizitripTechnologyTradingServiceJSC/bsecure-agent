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
	reFailed  = regexp.MustCompile(`Failed (?:password|publickey) for (?:invalid user )?(\S+) from (\S+) port`)
	reInvalid = regexp.MustCompile(`Invalid user (\S+) from (\S+)`)
)

// ParseSSH turns an auth.log line into a normalised event. The username is redacted from the raw line.
func ParseSSH(line string, now time.Time) *Event {
	for _, re := range []*regexp.Regexp{reFailed, reInvalid} {
		m := re.FindStringSubmatchIndex(line)
		if m == nil {
			continue
		}
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

// Tail polls a file from its current end, handling truncation/rotation.
type Tail struct {
	Path   string
	offset int64
	init   bool
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
		t.offset, t.init = st.Size(), true
		return nil, nil
	}
	if st.Size() < t.offset {
		t.offset = 0
	}
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
