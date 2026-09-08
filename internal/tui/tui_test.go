package tui

import (
	"strings"
	"testing"
)

func TestBadges(t *testing.T) {
	for _, s := range []string{
		RelayBadge(), DualStackBadge(), ExcludedBadge(), V6OnlyBadge(), Yes(), No(), NoHTTP(),
		HTTPSAutoDisabled(), HTTPSRange(), HTTPSReady(8080),
	} {
		if s == "" {
			t.Fatal("empty badge")
		}
	}
	if !strings.Contains(HTTPSReady(8080), "8081") {
		t.Fatalf("HTTPSReady should predict +1 port, got %q", HTTPSReady(8080))
	}
	cases := []struct {
		ex, v4, v6 bool
		want       string
	}{
		{true, true, true, ExcludedBadge()},
		{false, true, false, RelayBadge()},
		{false, true, true, DualStackBadge()},
		{false, false, true, V6OnlyBadge()},
		{false, false, false, "-"},
	}
	for _, c := range cases {
		if got := RelayAction(c.ex, c.v4, c.v6); got != c.want {
			t.Fatalf("RelayAction(%v,%v,%v)=%q want %q", c.ex, c.v4, c.v6, got, c.want)
		}
	}
	if BoolBadge(true) != Yes() || BoolBadge(false) != No() {
		t.Fatal("BoolBadge mismatch")
	}
	out := RenderTable([]string{"A", "B"}, [][]string{{"1", "2"}})
	if !strings.Contains(out, "1") || !strings.Contains(out, "A") {
		t.Fatalf("RenderTable missing content: %q", out)
	}
}
