package agent

import (
	"os"
	"strconv"
	"strings"
	"time"
)

// SelfStats lets the agent report what it costs the host, so the panel can show it (and a slow server can be cleared of blame).
type SelfStats struct {
	cpuPrev, wallPrev float64
	linesPrev         int64
	Lines             int64 // log lines read since start
	hz                float64
}

type StatsOut struct {
	CPUPct      float64 `json:"cpuPct"`
	RSSMB       float64 `json:"rssMB"`
	LinesPerSec float64 `json:"linesPerSec"`
	Dropped     int     `json:"dropped"`
	Keys        int     `json:"keys"`
}

func cpuSeconds(root string) float64 {
	b, err := os.ReadFile(root + "/proc/self/stat")
	if err != nil {
		return 0
	}
	s := string(b)
	i := strings.LastIndexByte(s, ')') // the command name may contain spaces
	if i < 0 {
		return 0
	}
	f := strings.Fields(s[i+1:])
	if len(f) < 13 {
		return 0
	}
	ut, _ := strconv.ParseFloat(f[11], 64)
	st, _ := strconv.ParseFloat(f[12], 64)
	return (ut + st) / 100 // USER_HZ is 100 on every Linux build Go supports
}

func rssMB(root string) float64 {
	b, err := os.ReadFile(root + "/proc/self/statm")
	if err != nil {
		return 0
	}
	f := strings.Fields(string(b))
	if len(f) < 2 {
		return 0
	}
	pages, _ := strconv.ParseFloat(f[1], 64)
	return pages * float64(os.Getpagesize()) / (1 << 20)
}

// Sample returns usage since the previous call.
func (s *SelfStats) Sample(now time.Time, dropped, keys int) StatsOut {
	cpu, wall := cpuSeconds(""), float64(now.UnixNano())/1e9
	out := StatsOut{RSSMB: rssMB(""), Dropped: dropped, Keys: keys}
	if s.wallPrev > 0 && wall > s.wallPrev {
		out.CPUPct = (cpu - s.cpuPrev) / (wall - s.wallPrev) * 100
		out.LinesPerSec = float64(s.Lines-s.linesPrev) / (wall - s.wallPrev)
	}
	s.cpuPrev, s.wallPrev, s.linesPrev = cpu, wall, s.Lines
	return out
}

// countCache avoids running external commands (nft) on every heartbeat for a number that rarely changes.
type countCache struct {
	at time.Time
	v  int
}

func (c *countCache) get(f func() int) int {
	if time.Since(c.at) > 2*time.Minute {
		c.v, c.at = f(), time.Now()
	}
	return c.v
}

// Invalidate forces the next get to recompute (called after a firewall change).
func (c *countCache) Invalidate() { c.at = time.Time{} }
