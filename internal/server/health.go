package server

import (
	"fmt"
	"net/http"
	"time"

	"k8s.io/component-base/metrics/legacyregistry"

	"github.com/awslabs/cedar-access-control-for-k8s/internal/server/options"
)

func newHealthHandlers() *http.ServeMux {
	mux := http.NewServeMux()
	// TODO: actually check health status
	mux.HandleFunc("/healthz", healthzHandlerFunc())
	mux.HandleFunc("/readyz", healthzHandlerFunc())
	mux.Handle("/metrics", legacyregistry.Handler())
	return mux
}

func healthzHandlerFunc() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}
}

// NewMetrics returns a new metrics server.
func NewMetricsServer() *http.Server {
	return &http.Server{
		Addr:         fmt.Sprintf("%s:%d", options.CedarAuthorizerDefaultAddress, options.CedarAuthorizerMetricsPort),
		Handler:      newHealthHandlers(),
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	}
}
