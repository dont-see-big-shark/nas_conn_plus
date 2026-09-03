package metrics

import (
	"io"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestObserveAndHandler(t *testing.T) {
	ObserveReconcile(5*time.Millisecond, nil)
	ObserveReconcile(time.Millisecond, io.ErrUnexpectedEOF)
	ObserveProbe(true)
	ObserveProbe(false)
	rec := httptest.NewRecorder()
	Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	body := rec.Body.String()
	for _, k := range []string{"nasconn_reconciles_total", "nasconn_reconcile_errors_total", "nasconn_probes_total", "nasconn_probes_http_total"} {
		if !strings.Contains(body, k) {
			t.Fatalf("missing metric %s in %q", k, body)
		}
	}
}
