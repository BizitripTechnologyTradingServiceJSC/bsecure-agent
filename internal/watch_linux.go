//go:build linux

package agent

import (
	"os"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

// Watcher wakes the main loop shortly after a watched log file changes, so events are seen within a fraction of a
// second without polling. Wakeups are coalesced (at most one per `debounce`), so a log written thousands of times a
// second costs a handful of wakeups. Rotation is handled by the periodic poll plus a re-arm on IN_MOVE_SELF/IN_DELETE_SELF.
type Watcher struct {
	fd       *os.File
	raw      int
	all      []string // everything we were asked to watch, for re-arming after rotation
	mu       sync.Mutex
	Wake     chan struct{}
	debounce time.Duration
	pending  bool
}

const inMask = syscall.IN_MODIFY | syscall.IN_MOVE_SELF | syscall.IN_DELETE_SELF | syscall.IN_ATTRIB

func NewWatcher(paths []string, debounce time.Duration) (*Watcher, error) {
	fd, err := syscall.InotifyInit1(syscall.IN_CLOEXEC | syscall.IN_NONBLOCK)
	if err != nil {
		return nil, err
	}
	w := &Watcher{raw: fd, fd: os.NewFile(uintptr(fd), "inotify"), all: append([]string(nil), paths...), Wake: make(chan struct{}, 1), debounce: debounce}
	w.Arm(paths)
	go w.loop()
	return w, nil
}

// Arm (re)registers watches; it is cheap and idempotent, and is called again after rotation.
func (w *Watcher) Arm(paths []string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, p := range paths {
		_, _ = syscall.InotifyAddWatch(w.raw, p, inMask) // same inode: same watch; missing file: the periodic poll retries
	}
}

func (w *Watcher) Close() { w.fd.Close() }

func (w *Watcher) signal() {
	w.mu.Lock()
	if w.pending {
		w.mu.Unlock()
		return
	}
	w.pending = true
	w.mu.Unlock()
	time.AfterFunc(w.debounce, func() {
		w.mu.Lock()
		w.pending = false
		w.mu.Unlock()
		select {
		case w.Wake <- struct{}{}:
		default:
		}
	})
}

func (w *Watcher) loop() {
	buf := make([]byte, 4096)
	for {
		n, err := w.fd.Read(buf) // parked in the runtime poller, not on an OS thread
		if err != nil {
			return
		}
		rearm := false
		for off := 0; off+syscall.SizeofInotifyEvent <= n; {
			ev := (*syscall.InotifyEvent)(unsafe.Pointer(&buf[off]))
			if ev.Mask&(syscall.IN_MOVE_SELF|syscall.IN_DELETE_SELF|syscall.IN_IGNORED) != 0 {
				rearm = true
			}
			off += syscall.SizeofInotifyEvent + int(ev.Len)
		}
		if rearm { // the file was rotated away: watch whatever is at the path now (may not exist yet; the poll retries)
			time.AfterFunc(500*time.Millisecond, func() { w.Arm(w.all) })
		}
		w.signal()
	}
}
