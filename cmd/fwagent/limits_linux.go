//go:build linux

package main

import (
	"log"
	"runtime"
	"runtime/debug"
	"syscall"
)

// limitSelf keeps the agent a polite guest on a production host, even when run without the systemd unit:
// lowest-but-one CPU priority, two OS threads at most, and a soft memory ceiling that makes the GC work harder
// instead of growing. (The systemd unit adds hard cgroup limits on top.)
func limitSelf() {
	if err := syscall.Setpriority(syscall.PRIO_PROCESS, 0, 10); err != nil {
		log.Printf("nice: %v", err)
	}
	runtime.GOMAXPROCS(min(runtime.NumCPU(), 2))
	debug.SetMemoryLimit(96 << 20)
}
