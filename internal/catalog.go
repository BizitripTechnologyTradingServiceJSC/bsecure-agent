package agent

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// The complete list of settings the agent is willing to change. Anything not here is refused,
// and every value is validated here regardless of what the Control Panel sends.
type settingDef struct {
	canon    string
	validate func(v string) error
}

func oneOf(vals ...string) func(string) error {
	return func(v string) error {
		for _, x := range vals {
			if v == x {
				return nil
			}
		}
		return fmt.Errorf("value must be one of %v", vals)
	}
}

func intRange(lo, hi int) func(string) error {
	return func(v string) error {
		n, err := strconv.Atoi(v)
		if err != nil || n < lo || n > hi {
			return fmt.Errorf("value must be an integer in %d..%d", lo, hi)
		}
		return nil
	}
}

func each(v string, f func(string) error) error {
	parts := strings.Split(v, ",")
	for _, p := range parts {
		if p = strings.TrimSpace(p); p == "" {
			return fmt.Errorf("empty list item")
		}
		if err := f(p); err != nil {
			return err
		}
	}
	return nil
}

// allowList accepts IPs/CIDRs but rejects "allow everyone" style ranges.
func allowList(v string) error {
	return each(v, func(s string) error {
		if p, err := netip.ParsePrefix(s); err == nil {
			min := 8
			if p.Addr().Is6() {
				min = 16
			}
			if p.Bits() < min {
				return fmt.Errorf("%s is too broad", s)
			}
			return nil
		}
		if _, err := netip.ParseAddr(s); err != nil {
			return fmt.Errorf("%q is not an IP or CIDR", s)
		}
		return nil
	})
}

func portList(v string) error {
	return each(v, func(s string) error { return intRange(1, 65535)(s) })
}

func singleIP(v string) error {
	if _, err := netip.ParseAddr(v); err != nil {
		return fmt.Errorf("not an IP address")
	}
	return nil
}

var catalog = map[string]map[string]settingDef{
	"sshd": {
		"permitrootlogin":        {"PermitRootLogin", oneOf("no", "prohibit-password")},
		"passwordauthentication": {"PasswordAuthentication", oneOf("no")},
		"permitemptypasswords":   {"PermitEmptyPasswords", oneOf("no")},
		"x11forwarding":          {"X11Forwarding", oneOf("no")},
		"maxauthtries":           {"MaxAuthTries", intRange(2, 6)},
	},
	"nginx": {
		"server_tokens": {"server_tokens", oneOf("off")},
		"ssl_protocols": {"ssl_protocols", oneOf("TLSv1.2 TLSv1.3", "TLSv1.3")},
	},
	"tinyproxy": {
		"allow":       {"Allow", allowList},
		"connectport": {"ConnectPort", portList},
		"listen":      {"Listen", singleIP},
	},
}

// ValidateSetting returns the canonical key name for an allowed (software, key, value).
func ValidateSetting(software, key, value string) (string, error) {
	defs, ok := catalog[software]
	if !ok {
		return "", fmt.Errorf("software %q not supported", software)
	}
	d, ok := defs[strings.ToLower(key)]
	if !ok {
		return "", fmt.Errorf("setting %s.%s cannot be changed", software, key)
	}
	if strings.ContainsAny(value, "\n\r;{}$`\"'\\#") {
		return "", fmt.Errorf("value contains forbidden characters")
	}
	if err := d.validate(value); err != nil {
		return "", err
	}
	return d.canon, nil
}
