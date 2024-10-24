package metrics

import (
	"context"

	apiv1alpha1 "github.com/awslabs/cedar-access-control-for-k8s/api/v1alpha1"
	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/component-base/metrics"
	"k8s.io/component-base/metrics/legacyregistry"
	"k8s.io/klog/v2"
)

const (
	// subSystemName is the name of this subsystem name used for prometheus metrics.
	subSystemName = "cedar_authorizer"
)

type registerables []metrics.Registerable

// init registers all metrics
func init() {
	for _, metric := range toRegister {
		legacyregistry.MustRegister(metric)
	}
}

var (
	requestTotal = metrics.NewCounterVec(
		&metrics.CounterOpts{
			Name:           "request_total",
			Subsystem:      subSystemName,
			Help:           "Number of HTTP requests partitioned by authorization decision.",
			StabilityLevel: metrics.ALPHA,
		},
		[]string{"decision"},
	)

	requestLatency = metrics.NewHistogramVec(
		&metrics.HistogramOpts{
			Name:           "request_duration_seconds",
			Subsystem:      subSystemName,
			Help:           "Request latency in seconds partitioned by authorization decision.",
			Buckets:        []float64{0.25, 0.5, 0.7, 1, 1.5, 3, 5, 10},
			StabilityLevel: metrics.ALPHA,
		},
		[]string{"decision"},
	)

	e2eLatency = metrics.NewHistogramVec(
		&metrics.HistogramOpts{
			Name:           "e2e_latency_seconds",
			Subsystem:      subSystemName,
			Help:           "End to end latency in seconds partitioned by filename.",
			Buckets:        prometheus.ExponentialBuckets(2, 2, 8),
			StabilityLevel: metrics.ALPHA,
		},
		[]string{"filename"},
	)

	toRegister = registerables{
		requestTotal,
		requestLatency,
		e2eLatency,
	}
)

// RecordRequestTotal increments the total number of requests for the webhook.
func RecordRequestTotal(ctx context.Context, decision string) {
	requestTotal.WithContext(ctx).With(map[string]string{"decision": decision}).Add(1)
}

// RecordRequestLatency measures request latency in seconds for the delegated authorization. Broken down by status code.
func RecordRequestLatency(ctx context.Context, decision string, latency float64) {
	requestLatency.WithContext(ctx).With(map[string]string{"decision": decision}).Observe(latency)
}

// RecordE2ELatency measures the e2e latency in seconds from ddb update time to load time.
func RecordE2ELatency(ctx context.Context, filename string, latency float64, clusterId, version string) {
	e2eLatency.WithContext(ctx).With(map[string]string{"filename": filename}).Observe(latency)
	klog.V(3).Infof("%#v", apiv1alpha1.E2ELatencyLog{
		ClusterID: clusterId,
		Version:   version,
		Type:      filename,
		Latency:   latency,
	})
}
