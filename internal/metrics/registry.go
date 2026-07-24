// Package metrics defines the xk6-bgp custom metrics and the helper
// that pushes per-Peer samples through the VU's Samples channel.
package metrics

import (
	"context"
	"fmt"
	"time"

	"go.k6.io/k6/metrics"
)

// Metrics is the xk6-bgp metric set, registered once per VU module
// instance. PrefixReceivedDuration is "T_received on the downstream peer
// minus T_submitted on the sender" — how long the DUT takes to
// deliver the UPDATE end-to-end. Both Trend metrics carry their
// samples in microseconds; the unit is documented in README's metric
// table rather than embedded in the metric name (k6 convention).
type Metrics struct {
	SessionUp              *metrics.Metric // Trend, µs — OPEN→Established
	PrefixReceivedDuration *metrics.Metric // Trend, µs — sender T_tx → receiver T_rx of the last prefix
	PrefixReceived         *metrics.Metric // Counter — cumulative NLRI count
	PrefixSent             *metrics.Metric // Counter — cumulative advertised NLRI count
	RouteRefreshDuration   *metrics.Metric // Trend, µs — ROUTE-REFRESH write → EoRR read (RFC 7313)
}

// Register installs the xk6-bgp metrics on the given Registry. Safe to
// call once per VU module instance; metrics already registered are
// returned as-is by k6's Registry.
//
// ValueType=Default (not Time). k6's Time type implies milliseconds;
// these are µs.
func Register(r *metrics.Registry) (*Metrics, error) {
	m := &Metrics{}
	var err error
	if m.SessionUp, err = r.NewMetric("bgp_session_up", metrics.Trend); err != nil {
		return nil, fmt.Errorf("bgp_session_up: %w", err)
	}
	if m.PrefixReceivedDuration, err = r.NewMetric("bgp_prefix_received_duration", metrics.Trend); err != nil {
		return nil, fmt.Errorf("bgp_prefix_received_duration: %w", err)
	}
	if m.PrefixReceived, err = r.NewMetric("bgp_prefix_received", metrics.Counter); err != nil {
		return nil, fmt.Errorf("bgp_prefix_received: %w", err)
	}
	if m.PrefixSent, err = r.NewMetric("bgp_prefix_sent", metrics.Counter); err != nil {
		return nil, fmt.Errorf("bgp_prefix_sent: %w", err)
	}
	if m.RouteRefreshDuration, err = r.NewMetric("bgp_route_refresh_duration", metrics.Trend); err != nil {
		return nil, fmt.Errorf("bgp_route_refresh_duration: %w", err)
	}
	return m, nil
}

// PushTrendMicros sends a single Trend sample expressed in µs.
func PushTrendMicros(ctx context.Context, samples chan<- metrics.SampleContainer, m *metrics.Metric, tags *metrics.TagSet, micros int64) {
	pushSample(ctx, samples, m, tags, float64(micros))
}

// PushCounter sends a single Counter sample.
func PushCounter(ctx context.Context, samples chan<- metrics.SampleContainer, m *metrics.Metric, tags *metrics.TagSet, n float64) {
	pushSample(ctx, samples, m, tags, n)
}

func pushSample(ctx context.Context, samples chan<- metrics.SampleContainer, m *metrics.Metric, tags *metrics.TagSet, value float64) {
	if m == nil || samples == nil {
		return
	}
	metrics.PushIfNotDone(ctx, samples, metrics.Sample{
		TimeSeries: metrics.TimeSeries{Metric: m, Tags: tags},
		Time:       time.Now(),
		Value:      value,
	})
}

// BuildPeerTags branches the VU's RunTags with xk6-bgp specific tags.
// plane=control is fixed; peer is the JS-side tag, empty when the user
// did not supply one (cardinality discipline).
func BuildPeerTags(root *metrics.TagSet, peerTag string) *metrics.TagSet {
	tags := root.With("plane", "control")
	if peerTag != "" {
		tags = tags.With("peer", peerTag)
	}
	return tags
}
