package agent

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"time"
)

// Command is the signed payload created by the Control Panel.
type Command struct {
	ID        string `json:"id"`
	ServerID  string `json:"serverId"`
	Action    string `json:"action"`
	Params    Params `json:"params"`
	ExpiresAt string `json:"expiresAt"`
	Nonce     string `json:"nonce"`
}

type Params struct {
	IP         string `json:"ip,omitempty"`
	TTLSeconds int    `json:"ttlSeconds,omitempty"`
	// set_config / confirm_config
	Software   string `json:"software,omitempty"`
	Key        string `json:"key,omitempty"`
	Value      string `json:"value,omitempty"`
	ConfirmSec int    `json:"confirmSec,omitempty"`
	ChangeID   string `json:"changeId,omitempty"`
}

const (
	MaxBlockTTL = 7 * 24 * 3600
	MinBlockTTL = 60
)

// Fixed action set. There is no shell passthrough: anything else is rejected.
var allowedActions = map[string]bool{"block_ip": true, "unblock_ip": true, "set_config": true, "confirm_config": true}

var changeIDRe = regexp.MustCompile(`^[0-9a-f]{24}$`)

// Verify checks signature, server binding, expiry, replay, action allowlist and parameters.
func Verify(pub ed25519.PublicKey, serverID, payload, sigB64 string, now time.Time, seen func(nonce string) bool, guard *Guard) (*Command, error) {
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil || !ed25519.Verify(pub, []byte(payload), sig) {
		return nil, errors.New("invalid signature")
	}
	var c Command
	if err := json.Unmarshal([]byte(payload), &c); err != nil {
		return nil, fmt.Errorf("bad payload: %w", err)
	}
	if c.ServerID != serverID {
		return nil, errors.New("command is for a different server")
	}
	exp, err := time.Parse(time.RFC3339Nano, c.ExpiresAt)
	if err != nil || now.After(exp) {
		return nil, errors.New("command expired")
	}
	if seen(c.ID + c.Nonce) {
		return nil, errors.New("replayed command")
	}
	if !allowedActions[c.Action] {
		return nil, fmt.Errorf("action %q not allowed", c.Action)
	}
	switch c.Action {
	case "block_ip", "unblock_ip":
		ip, err := netip.ParseAddr(c.Params.IP)
		if err != nil {
			return nil, errors.New("invalid ip")
		}
		if err := guard.CheckIP(ip.Unmap()); err != nil {
			return nil, err
		}
		if c.Action == "block_ip" && (c.Params.TTLSeconds < MinBlockTTL || c.Params.TTLSeconds > MaxBlockTTL) {
			return nil, errors.New("ttlSeconds out of range")
		}
	case "set_config":
		key, err := ValidateSetting(c.Params.Software, c.Params.Key, c.Params.Value)
		if err != nil {
			return nil, err
		}
		c.Params.Key = key
		if c.Params.ConfirmSec == 0 {
			c.Params.ConfirmSec = 120
		}
		if c.Params.ConfirmSec < 30 || c.Params.ConfirmSec > 900 {
			return nil, errors.New("confirmSec out of range 30..900")
		}
	case "confirm_config":
		if !changeIDRe.MatchString(c.Params.ChangeID) {
			return nil, errors.New("invalid changeId")
		}
	}
	return &c, nil
}

// Guard holds local safety rules that the panel cannot override.
type Guard struct {
	Allow []netip.Prefix // admin IPs/CIDRs that are never blocked
}

func ParseGuard(list []string) (*Guard, error) {
	g := &Guard{}
	for _, s := range list {
		if s == "" {
			continue
		}
		if p, err := netip.ParsePrefix(s); err == nil {
			g.Allow = append(g.Allow, p.Masked())
			continue
		}
		a, err := netip.ParseAddr(s)
		if err != nil {
			return nil, fmt.Errorf("bad allowlist entry %q", s)
		}
		g.Allow = append(g.Allow, netip.PrefixFrom(a, a.BitLen()))
	}
	return g, nil
}

func (g *Guard) CheckIP(ip netip.Addr) error {
	if ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() {
		return errors.New("refusing loopback/unspecified/multicast address")
	}
	for _, p := range g.Allow {
		if p.Contains(ip) {
			return errors.New("ip is in local admin allowlist")
		}
	}
	return nil
}
