package logger

import (
	"bytes"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
)

func TestLogger_New_DefaultAndNoColor(t *testing.T) {
	// Test default logger
	l1 := New()
	if l1 == nil {
		t.Fatal("expected non-nil logger")
	}

	// Test NO_COLOR environment variable
	t.Setenv("NO_COLOR", "1")
	l2 := New()
	if l2.useColor {
		t.Errorf("expected useColor=false when NO_COLOR is set")
	}
	if !strings.Contains(l2.tagInfo, "[INFO]") {
		t.Errorf("expected tagInfo to contain '[INFO]', got %s", l2.tagInfo)
	}

	// Test TERM=dumb
	t.Setenv("NO_COLOR", "")
	t.Setenv("TERM", "dumb")
	l3 := New()
	if l3.useColor {
		t.Errorf("expected useColor=false when TERM=dumb")
	}
}

func TestLogger_LoggingMethods(t *testing.T) {
	tests := []struct {
		name     string
		useColor bool
	}{
		{"colored", true},
		{"no_color", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := &bytes.Buffer{}
			l := New()
			l.mu.Lock()
			l.out = buf
			l.useColor = tt.useColor
			if !tt.useColor {
				l.tagInfo = "[INFO]"
				l.tagAdd = "[ + ]"
				l.tagStop = "[ - ]"
				l.tagReload = "[ ~ ]"
				l.tagWarn = "[ ! ]"
			}
			l.mu.Unlock()

			l.Info("info message %d", 1)
			if !strings.Contains(buf.String(), "info message 1") {
				t.Errorf("expected info output, got: %s", buf.String())
			}
			buf.Reset()

			l.Add("add message %s", "test")
			if !strings.Contains(buf.String(), "add message test") {
				t.Errorf("expected add output, got: %s", buf.String())
			}
			buf.Reset()

			l.Stop("stop message %s", "service")
			if !strings.Contains(buf.String(), "stop message service") {
				t.Errorf("expected stop output, got: %s", buf.String())
			}
			buf.Reset()

			l.Reload("reload message")
			if !strings.Contains(buf.String(), "reload message") {
				t.Errorf("expected reload output, got: %s", buf.String())
			}
			buf.Reset()

			l.Warn("warning %s", "alert")
			if !strings.Contains(buf.String(), "warning alert") {
				t.Errorf("expected warn output, got: %s", buf.String())
			}
		})
	}
}

func TestLogger_ConcurrentLogging(t *testing.T) {
	buf := &bytes.Buffer{}
	l := New()
	l.out = buf

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			l.Info("concurrent log %d", id)
			l.Add("adding %d", id)
			l.Warn("warning %d", id)
		}(i)
	}
	wg.Wait()

	out := buf.String()
	if !strings.Contains(out, "concurrent log") {
		t.Error("expected concurrent log output")
	}
}

func TestLogger_Banner(t *testing.T) {
	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	l := New()
	l.useColor = true
	l.Banner("1.0.0-test")

	l.useColor = false
	l.Banner("1.0.0-plain")

	w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	output := buf.String()

	if !strings.Contains(output, "nasconn+ v1.0.0-test") {
		t.Errorf("expected banner to contain version '1.0.0-test', got:\n%s", output)
	}
	if !strings.Contains(output, "nasconn+ v1.0.0-plain") {
		t.Errorf("expected banner to contain version '1.0.0-plain', got:\n%s", output)
	}
}
