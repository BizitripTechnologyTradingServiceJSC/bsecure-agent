package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Rollup is what the panel stores: how many times one source address did one thing in one minute, plus
// one sample line. A flood of 100 000 attempts from one address costs one row, not 100 000.
type Rollup struct {
	B      string   `json:"b"` // start of the minute
	Type   string   `json:"type"`
	IP     string   `json:"ip"`
	Src    string   `json:"src"`
	N      int      `json:"n"` // attempts since the previous flush of this key (the panel adds them up)
	First  string   `json:"first"`
	Last   string   `json:"last"`
	Users  []string `json:"users"`
	Sample string   `json:"sample,omitempty"`
}

type rkey struct {
	minute int64 // unix seconds, floored to the minute
	typ    string
	ip     string
}

type bucket struct {
	src         string
	n, pending  int
	first, last time.Time
	users       []string // raw names, at most maxUsers; never leave this process (only their hashes do)
	sample      string
	sampleSent  bool
}

const (
	maxUsers      = 16
	maxKeys       = 20000 // memory bound under a flood from a huge number of addresses
	maxRare       = 500
	hotThreshold  = 10   // a key with this many unsent attempts asks for an early flush
	maxPerRequest = 1000 // the panel accepts at most this many rollups per request
	sampleLen     = 160
)

// Aggregator folds events into per-(minute, type, ip) counters in memory. Not safe for concurrent use:
// the agent feeds and drains it from its single main loop.
type Aggregator struct {
	m       map[rkey]*bucket
	rare    []Event // events with no source address (sudo, OOM, new user...): few, kept individually
	hot     bool
	Dropped int // events discarded because a cap was hit
}

func NewAggregator() *Aggregator { return &Aggregator{m: map[rkey]*bucket{}} }

// Keys is the number of live counters (reported in the heartbeat so memory use is visible).
func (g *Aggregator) Keys() int { return len(g.m) }

// Hot reports whether some key has piled up enough unsent attempts to justify flushing before the next tick.
func (g *Aggregator) Hot() bool { return g.hot }

func (g *Aggregator) Add(e Event, at time.Time) {
	if e.IP == "" {
		if len(g.rare) >= maxRare {
			g.Dropped++
			return
		}
		g.rare = append(g.rare, e)
		return
	}
	k := rkey{at.Unix() / 60 * 60, e.Type, e.IP}
	b := g.m[k]
	if b == nil {
		if len(g.m) >= maxKeys {
			g.Dropped++
			return
		}
		b = &bucket{src: e.Source, first: at, sample: sampleOf(e.Line, e.IP)}
		g.m[k] = b
	}
	b.n++
	b.pending++
	b.last = at
	if b.pending == hotThreshold {
		g.hot = true
	}
	if e.User != "" && len(b.users) < maxUsers {
		u := e.User
		for _, x := range b.users {
			if x == u {
				u = ""
				break
			}
		}
		if u != "" {
			b.users = append(b.users, u)
		}
	}
}

// Drain returns the unsent deltas (oldest first) and clears them. If sending fails, hand them back to Requeue.
// Counters of minutes that are over and fully sent are forgotten, which bounds memory by what happened in the last ~2 minutes.
func (g *Aggregator) Drain(now time.Time) (rs []Rollup, rare []Event) {
	cutoff := now.Unix()/60*60 - 120
	for k, b := range g.m {
		if b.pending > 0 {
			rs = append(rs, b.rollup(k, b.pending))
			b.pending = 0
			b.sampleSent = true
		}
		if k.minute < cutoff {
			delete(g.m, k)
		}
	}
	sort.Slice(rs, func(i, j int) bool { return rs[i].B < rs[j].B })
	rare, g.rare, g.hot = g.rare, nil, false
	return rs, rare
}

// Requeue puts unsent deltas back after a failed upload. Rollups older than the panel's acceptance window are dropped.
func (g *Aggregator) Requeue(rs []Rollup, rare []Event, now time.Time) {
	for _, r := range rs {
		t, err := time.Parse(time.RFC3339, r.B)
		if err != nil || now.Sub(t) > 5*time.Hour {
			g.Dropped += r.N
			continue
		}
		k := rkey{t.Unix(), r.Type, r.IP}
		b := g.m[k]
		if b == nil {
			if len(g.m) >= maxKeys {
				g.Dropped += r.N
				continue
			}
			f, _ := time.Parse(time.RFC3339, r.First)
			b = &bucket{src: r.Src, first: f}
			g.m[k] = b
		}
		b.n += r.N
		b.pending += r.N
		if r.Sample != "" {
			b.sample, b.sampleSent = r.Sample, false
		}
		if b.pending >= hotThreshold {
			g.hot = true
		}
	}
	if free := maxRare - len(g.rare); len(rare) > free {
		g.Dropped += len(rare) - max(free, 0)
		rare = rare[:max(free, 0)]
	}
	g.rare = append(rare, g.rare...)
}

func (b *bucket) rollup(k rkey, n int) Rollup {
	r := Rollup{B: time.Unix(k.minute, 0).UTC().Format(time.RFC3339), Type: k.typ, IP: k.ip, Src: b.src, N: n,
		First: b.first.UTC().Format(time.RFC3339), Last: b.last.UTC().Format(time.RFC3339), Users: make([]string, 0, len(b.users))}
	for _, u := range b.users {
		r.Users = append(r.Users, userToken(u))
	}
	if !b.sampleSent {
		r.Sample = b.sample
	}
	return r
}

// userToken must match the panel's: user names can be passwords typed by mistake, so only a short hash is sent.
func userToken(u string) string {
	h := sha256.Sum256([]byte(u))
	return hex.EncodeToString(h[:4])
}

var syslogPrefix = regexp.MustCompile(`^[A-Z][a-z]{2} +\d+ \d\d:\d\d:\d\d \S+ `)

// sampleOf is what is worth keeping of a line: no time/host prefix, no address (it is a column already), bounded.
func sampleOf(line, ip string) string {
	s := syslogPrefix.ReplaceAllString(line, "")
	if ip != "" {
		s = strings.ReplaceAll(s, ip, "<ip>")
	}
	return clip(s, sampleLen)
}
