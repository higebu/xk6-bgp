// Package debug provides on-demand CPU + heap profiling helpers for
// xk6-bgp benchmarks. Profiling is opt-in via JS — importing this
// package has no side effects. See bgp.StartCPUProfile for the
// JS-facing entry point.
package debug

import (
	"errors"
	"fmt"
	"os"
	"runtime/pprof"
	"sync"
	"time"
)

// StopFunc stops an active CPU profile (and writes the companion heap
// profile). Safe to call multiple times; only the first call has
// effect.
type StopFunc func() error

var active struct {
	mu sync.Mutex
	on bool
}

// StartCPUProfile begins a CPU profile written to path, optionally
// auto-stopping after seconds. Returns a Stop function that also dumps
// a heap profile to <path>.heap. Only one profile may be active per
// process at a time.
func StartCPUProfile(path string, seconds int) (StopFunc, error) {
	if path == "" {
		return nil, errors.New("xk6-bgp: cpu profile path is required")
	}
	if _, err := os.Stat(path); err == nil {
		return nil, fmt.Errorf("xk6-bgp: cpu profile path %q already exists", path)
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("xk6-bgp: stat %q: %w", path, err)
	}

	active.mu.Lock()
	if active.on {
		active.mu.Unlock()
		return nil, errors.New("xk6-bgp: a cpu profile is already active")
	}
	f, err := os.Create(path) // #nosec G304 -- path is intentional public API surface (bgp.startCPUProfile JS argument)
	if err != nil {
		active.mu.Unlock()
		return nil, fmt.Errorf("xk6-bgp: cpu profile create %q: %w", path, err)
	}
	if err := pprof.StartCPUProfile(f); err != nil {
		_ = f.Close()
		active.mu.Unlock()
		return nil, fmt.Errorf("xk6-bgp: cpu profile start: %w", err)
	}
	active.on = true
	active.mu.Unlock()

	var stopOnce sync.Once
	stop := func() error {
		var retErr error
		stopOnce.Do(func() {
			pprof.StopCPUProfile()
			if err := f.Close(); err != nil {
				retErr = fmt.Errorf("xk6-bgp: close cpu profile: %w", err)
			}
			if hp, err := os.Create(path + ".heap"); err == nil { // #nosec G304 -- companion path to the user-provided CPU profile path
				_ = pprof.WriteHeapProfile(hp)
				_ = hp.Close()
			}
			active.mu.Lock()
			active.on = false
			active.mu.Unlock()
		})
		return retErr
	}

	if seconds > 0 {
		go func() {
			time.Sleep(time.Duration(seconds) * time.Second)
			_ = stop()
		}()
	}

	return stop, nil
}
