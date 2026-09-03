package ipc

import (
	"strings"
	"testing"

	"github.com/dont-see-big-shark/nas_conn_plus/internal/proxy"
)

func TestFormatBytesNoPanic(t *testing.T) {
	for _, b := range []uint64{0, 1, 1023, 1024, 1 << 20, 1 << 30, 1 << 40, 1 << 50, 1 << 60, ^uint64(0)} {
		if got := formatBytes(b); got == "" {
			t.Fatalf("empty for %d", b)
		}
	}
}

func BenchmarkFormatBytes(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = formatBytes(123456789)
	}
}

func TestTruncateRunes(t *testing.T) {
	if got := truncateRunes("abc", 48); got != "abc" {
		t.Fatalf("short string changed: %q", got)
	}
	long := strings.Repeat("x", 100)
	got := truncateRunes(long, 48)
	if len([]rune(got)) != 49 { // 48 + ellipsis
		t.Fatalf("expected 49 runes, got %d", len([]rune(got)))
	}
	if got := truncateRunes("abc", 0); got != "" {
		t.Fatalf("expected empty, got %q", got)
	}
	// Multibyte-safe: never split a rune.
	mb := strings.Repeat("服", 100)
	if got := truncateRunes(mb, 48); len([]rune(got)) != 49 {
		t.Fatalf("multibyte truncation broke runes: %d", len([]rune(got)))
	}
}

func TestRenderStatusSanitizesUntrustedFields(t *testing.T) {
	report := &StatusReport{
		Version:       "1.0\x1b]0;PWNED\a",
		UptimeSeconds: -5, // hostile negative must not render "-5s"
		Listeners: []proxy.ListenerMetrics{
			{Kind: "relay", Name: "svc\x1b[31mRED\x1b[0m" + strings.Repeat("y", 200), Port: 8080, Backend: 8080},
		},
	}
	out := RenderStatus(report)
	if strings.Contains(out, "\x1b") {
		t.Error("rendered output contains ANSI escape from untrusted fields")
	}
	if strings.Contains(out, "-5s") || strings.Contains(out, "-5") {
		t.Errorf("negative uptime leaked into output: %q", out)
	}
}
