package bgp

import (
	"errors"

	"github.com/grafana/sobek"
	"go.k6.io/k6/js/common"

	"github.com/higebu/xk6-bgp/internal/debug"
)

// CPUProfile is the JS-facing handle returned by bgp.startCPUProfile.
// Call .stop() to flush the profile before the configured `seconds`
// elapses; calling it again is a no-op.
type CPUProfile struct {
	stop debug.StopFunc
}

// Stop flushes the CPU profile and writes the companion heap profile.
func (p *CPUProfile) Stop() error { return p.stop() }

// startCPUProfile is bound to JS as `bgp.startCPUProfile({path, seconds})`.
// path is required. seconds > 0 schedules an automatic stop; otherwise
// the caller is expected to invoke .stop() explicitly.
func (mi *ModuleInstance) startCPUProfile(arg sobek.Value) (*CPUProfile, error) {
	rt := mi.vu.Runtime()
	if common.IsNullish(arg) {
		return nil, errors.New("startCPUProfile: missing config argument {path, seconds?}")
	}
	obj := arg.ToObject(rt)
	if obj == nil {
		return nil, errors.New("startCPUProfile: config must be an object")
	}
	path := optString(obj, "path")
	seconds := int(optUint32(obj, "seconds"))
	stop, err := debug.StartCPUProfile(path, seconds)
	if err != nil {
		return nil, err
	}
	return &CPUProfile{stop: stop}, nil
}
