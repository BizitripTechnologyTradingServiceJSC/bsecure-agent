//go:build !linux

package agent

import (
	"errors"
	"time"
)

type Watcher struct{ Wake chan struct{} }

func NewWatcher([]string, time.Duration) (*Watcher, error) {
	return nil, errors.New("file watching needs Linux; polling is used")
}
func (w *Watcher) Arm([]string) {}
func (w *Watcher) Close()       {}
