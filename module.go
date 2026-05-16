// Package bgp is the k6/x/bgp extension entry point. xk6-bgp is a k6
// extension for benchmarking BGP daemons. See README.md and CLAUDE.md
// for design.
package bgp

import (
	"runtime/debug"

	"go.k6.io/k6/js/common"
	"go.k6.io/k6/js/modules"

	"github.com/higebu/xk6-bgp/internal/coord"
	xmetrics "github.com/higebu/xk6-bgp/internal/metrics"
)

func init() {
	modules.Register("k6/x/bgp", New())
}

// Version is the xk6-bgp release version exposed to JS as `bgp.version`.
// Override at build time with:
//
//	-ldflags "-X github.com/higebu/xk6-bgp.Version=v0.1.0"
//
// When the ldflag is not set, init() falls back to the module version
// recorded in the embedded build info (populated automatically when
// consumed as a Go module dependency, e.g. by `xk6 build`).
var Version = "dev"

func init() {
	if Version != "dev" {
		return
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return
	}
	const modPath = "github.com/higebu/xk6-bgp"
	if info.Main.Path == modPath && info.Main.Version != "" && info.Main.Version != "(devel)" {
		Version = info.Main.Version
		return
	}
	for _, dep := range info.Deps {
		if dep.Path == modPath && dep.Version != "" && dep.Version != "(devel)" {
			Version = dep.Version
			return
		}
	}
}

// RootModule is shared across every VU in the k6 process. Anything
// that needs cross-VU state (barriers, registries) lives on the root.
type RootModule struct {
	barriers *coord.Registry
}

func New() *RootModule {
	return &RootModule{barriers: coord.NewRegistry()}
}

func (r *RootModule) NewModuleInstance(vu modules.VU) modules.Instance {
	mi := &ModuleInstance{vu: vu, root: r}
	if env := vu.InitEnv(); env != nil && env.Registry != nil {
		m, err := xmetrics.Register(env.Registry)
		if err != nil {
			common.Throw(vu.Runtime(), err)
		}
		mi.metrics = m
	}
	return mi
}

type ModuleInstance struct {
	vu      modules.VU
	root    *RootModule
	metrics *xmetrics.Metrics
}

func (mi *ModuleInstance) Exports() modules.Exports {
	return modules.Exports{
		Default: map[string]any{
			"Peer":            mi.newPeer,
			"barrier":         mi.barrier,
			"startCPUProfile": mi.startCPUProfile,
			"version":         Version,
		},
	}
}
