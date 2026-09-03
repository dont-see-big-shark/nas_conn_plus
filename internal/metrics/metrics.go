package metrics

import (
	"fmt"
	"net/http"
	"sync/atomic"
	"time"
)

var (
	reconciles      atomic.Uint64
	reconcileErrors atomic.Uint64
	lastReconcileMs atomic.Int64
	probes          atomic.Uint64
	probeHTTP       atomic.Uint64
)

// ObserveReconcile records one reconcile cycle.
func ObserveReconcile(d time.Duration, err error) {
	reconciles.Add(1)
	lastReconcileMs.Store(int64(d / time.Millisecond))
	if err != nil {
		reconcileErrors.Add(1)
	}
}

// ObserveProbe records one HTTP probe result.
func ObserveProbe(isHTTP bool) {
	probes.Add(1)
	if isHTTP {
		probeHTTP.Add(1)
	}
}

// Handler exposes Prometheus exposition format without new deps.
func Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		fmt.Fprintf(w, "nasconn_reconciles_total %d\n", reconciles.Load())
		fmt.Fprintf(w, "nasconn_reconcile_errors_total %d\n", reconcileErrors.Load())
		fmt.Fprintf(w, "nasconn_reconcile_last_duration_ms %d\n", lastReconcileMs.Load())
		fmt.Fprintf(w, "nasconn_probes_total %d\n", probes.Load())
		fmt.Fprintf(w, "nasconn_probes_http_total %d\n", probeHTTP.Load())
	})
}
