package agent

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

const Version = "0.1.0"

type Config struct {
	PanelURL      string
	Name          string
	EnrollToken   string
	StateDir      string
	AuthLog       string
	NginxLog      string
	Syslog        string
	DryRun        bool
	Allowlist     []string
	AllowConfig   bool // opt-in: allow signed set_config commands to edit sshd/nginx/tinyproxy config
	PanelPubKey   string
	TLS           TLSConfig
	OverlayCIDRs  []string // VPN ranges that are never blocked (NetBird default 100.64.0.0/10)
	AllowInsecure bool     // permit http:// PANEL_URL (testing only) // base64 raw ed25519; pinned out-of-band, overrides what enroll returns
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
	outbox []result // command results not yet accepted by the panel (persisted)
	agg    *Aggregator
	stats  SelfStats
	// Log processing is capped at a fraction of one core: after a pass that took d, the next one waits d*(1/maxDuty-1).
	nextCollect time.Time
	lastFlush   time.Time
	watcher     *Watcher
	coll        *Collector // keeps its caches between inventories
	invHash     [32]byte
	invSent     time.Time
	nftCount    countCache
}

// maxDuty is the share of one CPU core the log reader may use. Under a flood the reader sheds load (skips ahead
// in the file, counts what it skipped) rather than burning more CPU or falling ever further behind.
const (
	maxDuty       = 0.10
	passLines     = 20000
	maxBacklog    = 8 << 20 // bytes still unread after a pass beyond which we skip ahead
	hotFlushEvery = 2 * time.Second
)

func New(cfg Config, fw Firewall) (*Agent, error) {
	g, err := ParseGuard(cfg.Allowlist)
	if err != nil {
		return nil, err
	}
	for _, c := range cfg.OverlayCIDRs {
		p, err := netip.ParsePrefix(strings.TrimSpace(c))
		if err != nil {
			return nil, fmt.Errorf("bad OVERLAY_CIDRS entry %q", c)
		}
		g.Overlay = append(g.Overlay, p.Masked())
	}
	hc, err := NewHTTPClient(cfg.PanelURL, cfg.TLS, cfg.AllowInsecure)
	if err != nil {
		return nil, err
	}
	return &Agent{cfg: cfg, fw: fw, cm: NewConfigManager(cfg.StateDir), guard: g, http: hc, seen: map[string]time.Time{}, tails: sources(cfg), agg: NewAggregator()}, nil
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
		return &httpError{res.StatusCode, fmt.Sprintf("%s %s: %d %s", method, path, res.StatusCode, data)}
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

// EnrollWithRetry keeps trying while the panel is unreachable or refuses (e.g. waiting for an admin to reset
// the enrollment), backing off 5s → 5min. Local configuration errors are returned immediately.
func (a *Agent) EnrollWithRetry(sleep func(time.Duration)) error {
	wait := 5 * time.Second
	for {
		err := a.Enroll()
		var he *httpError
		var ne net.Error
		if err == nil || !(errors.As(err, &he) || errors.As(err, &ne) || strings.Contains(err.Error(), "connection refused")) {
			return err
		}
		log.Printf("enroll failed, retrying in %s: %v", wait, err)
		sleep(wait)
		if wait *= 2; wait > 5*time.Minute {
			wait = 5 * time.Minute
		}
	}
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
	var resp struct {
		NeverBlock []string `json:"neverBlock"`
	}
	err := a.do("POST", "/agent/heartbeat", map[string]any{
		"agentVersion": Version, "os": runtime.GOOS + "/" + runtime.GOARCH, "dryRun": a.cfg.DryRun, "allowConfig": a.cfg.AllowConfig,
		"firewall": map[string]any{"backend": a.fw.Backend(), "ready": true, "blocked": a.nftCount.get(a.fw.Count)},
		"stats":    a.stats.Sample(time.Now(), a.agg.Dropped, a.agg.Keys()),
	}, &resp)
	if err == nil && resp.NeverBlock != nil {
		a.guard.AddNeverBlock(resp.NeverBlock)
	}
	return err
}

type logSource struct {
	tail  *Tail
	parse Parser
	quick func(line []byte) bool // cheap prefilter; the parser only sees lines it lets through
}

func sources(cfg Config) []*logSource {
	var out []*logSource
	nq := &nginxQuick{}
	for _, s := range []struct {
		path  string
		p     Parser
		quick func([]byte) bool
	}{{cfg.AuthLog, NewSSHParser().Parse, quickSSH}, {cfg.NginxLog, ParseNginxAccess, nq.Match}, {cfg.Syslog, ParseSyslog, quickSyslog}} {
		if s.path != "" {
			out = append(out, &logSource{&Tail{Path: s.path}, s.p, s.quick})
		}
	}
	return out
}

// CollectEvents reads new log lines from every configured source and folds the interesting ones into the
// aggregator. force bypasses the CPU duty cap (used at startup and by the periodic safety poll).
func (a *Agent) CollectEvents(force bool) {
	start := time.Now()
	if !force && start.Before(a.nextCollect) {
		return
	}
	for _, src := range a.tails {
		for pass := 0; pass < 4; pass++ {
			now := time.Now()
			backlog, err := src.tail.Each(passLines, func(b []byte) {
				a.stats.Lines++
				if n := len(b); n > 0 && b[n-1] == '\r' {
					b = b[:n-1]
				}
				if !src.quick(b) {
					return
				}
				if e := src.parse(string(b), now); e != nil {
					a.agg.Add(*e, now)
				}
			})
			if err != nil {
				break
			}
			if backlog > maxBacklog {
				skipped := src.tail.SkipToEnd()
				a.agg.Dropped += int(skipped / 150) // ~150 bytes per line, an estimate for the "dropped" counter
				log.Printf("log %s: %d MiB behind, skipped ahead (load shedding)", src.tail.Path, skipped>>20)
				break
			}
			if backlog == 0 {
				break
			}
		}
	}
	d := time.Since(start)
	a.nextCollect = time.Now().Add(time.Duration(float64(d) * (1/maxDuty - 1)))
}

// watchPaths are the log files worth waking up for.
func (a *Agent) watchPaths() []string {
	var ps []string
	for _, s := range a.tails {
		ps = append(ps, s.tail.Path)
	}
	return ps
}

// SendInventory reports ports, software versions and parsed settings (read-only facts). An unchanged inventory is
// not re-sent every 5 minutes: the panel only needs it again after invRefresh (it also serves as a liveness signal).
func (a *Agent) SendInventory() error {
	if a.coll == nil {
		a.coll = &Collector{Run: ExecRunner}
	}
	inv := a.coll.Collect()
	stamp := inv.CollectedAt
	inv.CollectedAt = ""
	b, _ := json.Marshal(inv)
	h := sha256.Sum256(b)
	if h == a.invHash && time.Since(a.invSent) < invRefresh {
		return nil
	}
	inv.CollectedAt = stamp
	if err := a.do("POST", "/agent/inventory", inv, nil); err != nil {
		return err
	}
	a.invHash, a.invSent = h, time.Now()
	return nil
}

const invRefresh = 30 * time.Minute

// FlushEvents uploads the unsent counters. On failure they go back into the aggregator and are retried with the
// next flush (their minute stays the key, so nothing is double-counted).
func (a *Agent) FlushEvents() error {
	now := time.Now()
	a.lastFlush = now
	rs, rare := a.agg.Drain(now)
	for i := 0; i < len(rs); i += maxPerRequest {
		chunk := rs[i:min(i+maxPerRequest, len(rs))]
		if err := a.do("POST", "/agent/rollups", map[string]any{"rollups": chunk}, nil); err != nil {
			var he *httpError
			if errors.As(err, &he) && he.code >= 400 && he.code < 500 && he.code != 429 {
				for _, r := range chunk { // the panel will never accept these rows: drop them instead of retrying forever
					a.agg.Dropped += r.N
				}
				log.Printf("rollups refused, dropped: %v", err)
				continue
			}
			a.agg.Requeue(rs[i:], rare, now)
			return err
		}
	}
	for i := 0; i < len(rare); i += 500 {
		chunk := rare[i:min(i+500, len(rare))]
		if err := a.do("POST", "/agent/events", map[string]any{"events": chunk}, nil); err != nil {
			a.agg.Requeue(nil, rare[i:], now)
			return err
		}
	}
	return nil
}

// flushIfHot sends early when a key piled up enough attempts that waiting for the next tick would delay noticing an attack.
func (a *Agent) flushIfHot() {
	if a.agg.Hot() && time.Since(a.lastFlush) >= hotFlushEvery {
		if err := a.FlushEvents(); err != nil {
			log.Printf("events: %v", err)
		}
	}
}

type httpError struct {
	code int
	msg  string
}

func (e *httpError) Error() string { return e.msg }

type result struct {
	ID     string `json:"id"`
	Status string `json:"status"`
	Output string `json:"output"`
}

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
	a.saveSeen() // replay protection must survive an agent restart within a command's validity window
	return false
}

func (a *Agent) seenPath() string { return filepath.Join(a.cfg.StateDir, "seen.json") }

func (a *Agent) saveSeen() {
	if a.cfg.StateDir == "" {
		return
	}
	b, _ := json.Marshal(a.seen)
	if err := os.WriteFile(a.seenPath(), b, 0o600); err != nil {
		log.Printf("save seen: %v", err)
	}
}

func (a *Agent) loadSeen() {
	if b, err := os.ReadFile(a.seenPath()); err == nil {
		_ = json.Unmarshal(b, &a.seen)
	}
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
		a.report(p.ID, status, out)
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
		a.nftCount.Invalidate()
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

// report sends a command result; if the panel is unreachable it is queued on disk and retried,
// so the panel never loses e.g. a "reverted" outcome. Results are delivered in order.
func (a *Agent) report(cmdID, status, out string) {
	a.outbox = append(a.outbox, result{cmdID, status, out})
	a.FlushOutbox()
}

func (a *Agent) FlushOutbox() {
	for len(a.outbox) > 0 {
		r := a.outbox[0]
		err := a.do("POST", "/agent/commands/"+r.ID+"/result", map[string]string{"status": r.Status, "output": r.Output}, nil)
		var he *httpError
		if err != nil && !(errors.As(err, &he) && he.code >= 400 && he.code < 500) {
			log.Printf("report result %s (queued, will retry): %v", r.ID, err)
			break // network/5xx: keep it and keep order
		}
		if err != nil {
			log.Printf("panel refused result %s, dropping: %v", r.ID, err)
		}
		a.outbox = a.outbox[1:]
	}
	if len(a.outbox) > 1000 {
		a.outbox = a.outbox[len(a.outbox)-1000:]
	}
	a.saveOutbox()
}

func (a *Agent) outboxPath() string { return filepath.Join(a.cfg.StateDir, "outbox.json") }

func (a *Agent) saveOutbox() {
	if a.cfg.StateDir == "" {
		return
	}
	b, _ := json.Marshal(a.outbox)
	if err := os.WriteFile(a.outboxPath(), b, 0o600); err != nil {
		log.Printf("save outbox: %v", err)
	}
}

func (a *Agent) loadOutbox() {
	if b, err := os.ReadFile(a.outboxPath()); err == nil {
		_ = json.Unmarshal(b, &a.outbox)
	}
}

// RevertDue undoes applied config changes whose confirmation window expired.
func (a *Agent) RevertDue() {
	for _, p := range a.cm.Due() {
		if err := a.cm.Revert(p); err != nil {
			n := a.cm.RevertFailed(p) // retried with backoff, not every 5s
			log.Printf("revert %s failed (attempt %d): %v", p.CmdID, n, err)
			if n == 1 {
				a.report(p.CmdID, "failed", trunc("auto-revert FAILED, manual action needed: "+err.Error()))
			}
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
	a.loadOutbox()
	a.loadSeen()
	a.CollectEvents(true) // position every log tail now, so lines written before the first tick are not skipped
	var wake <-chan struct{}
	if w, err := NewWatcher(a.watchPaths(), 200*time.Millisecond); err == nil {
		a.watcher, wake = w, w.Wake
		defer w.Close()
	} else {
		log.Printf("file watching unavailable, polling every 10s: %v", err)
	}
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
		case <-wake: // a log file changed (coalesced to ~5 wakeups/s at most)
			a.CollectEvents(false)
			a.flushIfHot()
		case <-ev.C: // safety poll (rotation, missed wakeups) and regular upload
			a.CollectEvents(true)
			if a.watcher != nil {
				a.watcher.Arm(a.watchPaths())
			}
			if err := a.FlushEvents(); err != nil {
				log.Printf("events: %v", err)
			}
		case <-cm.C:
			a.RevertDue() // before polling: a revert must not wait on the network
			a.flushIfHot()
			a.FlushOutbox()
			if err := a.PollCommands(); err != nil {
				log.Printf("commands: %v", err)
			}
		}
	}
}
