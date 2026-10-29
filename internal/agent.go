package agent

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"
)

const Version = "0.1.0"

type Config struct {
	PanelURL    string
	Name        string
	EnrollToken string
	StateDir    string
	AuthLog     string
	NginxLog    string
	Syslog      string
	DryRun      bool
	Allowlist   []string
	AllowConfig bool   // opt-in: allow signed set_config commands to edit sshd/nginx/tinyproxy config
	PanelPubKey string // base64 raw ed25519; pinned out-of-band, overrides what enroll returns
}

type state struct {
	ServerID string `json:"serverId"`
	Token    string `json:"token"`
	PubKey   string `json:"panelPublicKey"`
}

type Agent struct {
	cfg    Config
	http   *http.Client
	fw     Firewall
	cm     *ConfigManager
	guard  *Guard
	st     state
	pub    ed25519.PublicKey
	mu     sync.Mutex
	seen   map[string]time.Time
	tails  []*logSource
	events []Event
}

func New(cfg Config, fw Firewall) (*Agent, error) {
	g, err := ParseGuard(cfg.Allowlist)
	if err != nil {
		return nil, err
	}
	return &Agent{cfg: cfg, fw: fw, cm: NewConfigManager(cfg.StateDir), guard: g, http: &http.Client{Timeout: 15 * time.Second}, seen: map[string]time.Time{}, tails: sources(cfg)}, nil
}

func (a *Agent) do(method, path string, body, out any) error {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, a.cfg.PanelURL+path, rd)
	req.Header.Set("content-type", "application/json")
	if a.st.Token != "" {
		req.Header.Set("authorization", "Bearer "+a.st.Token)
	}
	res, err := a.http.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if res.StatusCode >= 300 {
		return fmt.Errorf("%s %s: %d %s", method, path, res.StatusCode, data)
	}
	if out != nil {
		return json.Unmarshal(data, out)
	}
	return nil
}

func (a *Agent) Enroll() error {
	sf := filepath.Join(a.cfg.StateDir, "state.json")
	if b, err := os.ReadFile(sf); err == nil && json.Unmarshal(b, &a.st) == nil && a.st.Token != "" {
		return a.loadKey()
	}
	if err := a.do("POST", "/agent/enroll", map[string]string{"name": a.cfg.Name, "enrollToken": a.cfg.EnrollToken}, &a.st); err != nil {
		return err
	}
	if err := os.MkdirAll(a.cfg.StateDir, 0o700); err != nil {
		return err
	}
	b, _ := json.Marshal(a.st)
	if err := os.WriteFile(sf, b, 0o600); err != nil {
		return err
	}
	return a.loadKey()
}

func (a *Agent) loadKey() error {
	k := a.cfg.PanelPubKey
	if k == "" {
		k = a.st.PubKey // trust-on-first-use; pin PANEL_PUBKEY in production
	}
	raw, err := base64.StdEncoding.DecodeString(k)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid panel public key")
	}
	a.pub = ed25519.PublicKey(raw)
	return nil
}

func (a *Agent) Heartbeat() error {
	return a.do("POST", "/agent/heartbeat", map[string]any{
		"agentVersion": Version, "os": runtime.GOOS + "/" + runtime.GOARCH, "dryRun": a.cfg.DryRun, "allowConfig": a.cfg.AllowConfig,
		"firewall": map[string]any{"backend": a.fw.Backend(), "ready": true, "blocked": a.fw.Count()},
	}, nil)
}

type logSource struct {
	tail  *Tail
	parse Parser
}

func sources(cfg Config) []*logSource {
	var out []*logSource
	for _, s := range []struct {
		path string
		p    Parser
	}{{cfg.AuthLog, ParseSSH}, {cfg.NginxLog, ParseNginxAccess}, {cfg.Syslog, ParseSyslog}} {
		if s.path != "" {
			out = append(out, &logSource{&Tail{Path: s.path}, s.p})
		}
	}
	return out
}

// CollectEvents reads new log lines from every configured source into the buffer.
func (a *Agent) CollectEvents() {
	for _, src := range a.tails {
		lines, err := src.tail.Read(500)
		if err != nil {
			continue
		}
		for _, l := range lines {
			if e := src.parse(l, time.Now()); e != nil {
				a.events = append(a.events, *e)
			}
		}
	}
	if len(a.events) > 5000 { // panel unreachable for a long time: keep the newest
		a.events = a.events[len(a.events)-5000:]
	}
}

// SendInventory reports ports, software versions and parsed settings (read-only facts).
func (a *Agent) SendInventory() error {
	c := &Collector{Run: ExecRunner}
	return a.do("POST", "/agent/inventory", c.Collect(), nil)
}

func (a *Agent) FlushEvents() error {
	if len(a.events) == 0 {
		return nil
	}
	n := min(len(a.events), 500)
	if err := a.do("POST", "/agent/events", map[string]any{"events": a.events[:n]}, nil); err != nil {
		return err
	}
	a.events = a.events[n:]
	return nil
}

type pending struct{ ID, Payload, Signature string }

func (a *Agent) seenFn(key string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	for k, t := range a.seen {
		if time.Since(t) > 2*time.Hour {
			delete(a.seen, k)
		}
	}
	if _, ok := a.seen[key]; ok {
		return true
	}
	a.seen[key] = time.Now()
	return false
}

func (a *Agent) PollCommands() error {
	var resp struct {
		Commands []struct {
			ID        string `json:"id"`
			Payload   string `json:"payload"`
			Signature string `json:"signature"`
		} `json:"commands"`
	}
	if err := a.do("GET", "/agent/commands", nil, &resp); err != nil {
		return err
	}
	for _, p := range resp.Commands {
		status, out := a.Execute(p.Payload, p.Signature)
		log.Printf("command %s -> %s: %s", p.ID, status, out)
		if err := a.do("POST", "/agent/commands/"+p.ID+"/result", map[string]string{"status": status, "output": out}, nil); err != nil {
			log.Printf("report result: %v", err)
		}
	}
	return nil
}

// Execute verifies and runs one command. Returns status: success|failed|dry_run|rejected.
func (a *Agent) Execute(payload, sig string) (string, string) {
	c, err := Verify(a.pub, a.st.ServerID, payload, sig, time.Now(), a.seenFn, a.guard)
	if err != nil {
		return "rejected", err.Error()
	}
	var out string
	switch c.Action {
	case "block_ip", "unblock_ip":
		ip := netip.MustParseAddr(c.Params.IP).Unmap()
		if c.Action == "block_ip" {
			out, err = a.fw.Block(ip, c.Params.TTLSeconds)
		} else {
			out, err = a.fw.Unblock(ip)
		}
	case "set_config":
		if !a.cfg.AllowConfig {
			return "rejected", "config changes are disabled on this agent (set ALLOW_CONFIG_CHANGES=true)"
		}
		return a.cm.Apply(c.ID, Change{c.Params.Software, c.Params.Key, c.Params.Value}, c.Params.ConfirmSec, a.cfg.DryRun)
	case "confirm_config":
		if !a.cfg.AllowConfig {
			return "rejected", "config changes are disabled on this agent"
		}
		if !a.cm.Confirm(c.Params.ChangeID) {
			return "failed", "no pending change with that id (already confirmed or reverted)"
		}
		a.report(c.Params.ChangeID, "confirmed", "confirmed by "+c.ID)
		return "success", "change confirmed, auto-revert cancelled"
	}
	if err != nil {
		return "failed", trunc(fmt.Sprintf("%s: %v", out, err))
	}
	if a.cfg.DryRun {
		return "dry_run", trunc(out)
	}
	return "success", trunc(out)
}

func (a *Agent) report(cmdID, status, out string) {
	if err := a.do("POST", "/agent/commands/"+cmdID+"/result", map[string]string{"status": status, "output": out}, nil); err != nil {
		log.Printf("report result: %v", err)
	}
}

// RevertDue undoes applied config changes whose confirmation window expired.
func (a *Agent) RevertDue() {
	for _, p := range a.cm.Due() {
		if err := a.cm.Revert(p); err != nil {
			log.Printf("revert %s failed: %v", p.CmdID, err)
			a.report(p.CmdID, "failed", trunc("auto-revert FAILED, manual action needed: "+err.Error()))
			continue
		}
		log.Printf("reverted %s.%s (not confirmed in time)", p.Software, p.Key)
		a.report(p.CmdID, "reverted", fmt.Sprintf("not confirmed in time; restored previous %s config", p.Software))
	}
}

func trunc(s string) string {
	if len(s) > 1500 {
		return s[:1500]
	}
	return s
}

// Run is the main loop: heartbeat 30s, events 10s, commands 5s. All connections are outbound.
func (a *Agent) Run() error {
	if err := a.fw.Setup(a.guard.Allow); err != nil {
		return err
	}
	hb, ev, cm, inv := time.NewTicker(30*time.Second), time.NewTicker(10*time.Second), time.NewTicker(5*time.Second), time.NewTicker(5*time.Minute)
	a.RevertDue() // changes left unconfirmed across an agent restart
	_ = a.Heartbeat()
	if err := a.SendInventory(); err != nil {
		log.Printf("inventory: %v", err)
	}
	for {
		select {
		case <-hb.C:
			if err := a.Heartbeat(); err != nil {
				log.Printf("heartbeat: %v", err)
			}
		case <-inv.C:
			if err := a.SendInventory(); err != nil {
				log.Printf("inventory: %v", err)
			}
		case <-ev.C:
			a.CollectEvents()
			if err := a.FlushEvents(); err != nil {
				log.Printf("events: %v", err)
			}
		case <-cm.C:
			a.RevertDue() // before polling: a revert must not wait on the network
			if err := a.PollCommands(); err != nil {
				log.Printf("commands: %v", err)
			}
		}
	}
}
