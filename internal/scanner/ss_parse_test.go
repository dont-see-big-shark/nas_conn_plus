package scanner

import (
	"testing"
	"time"
)

// P0-3: parseSSOutput must handle both `ss -tlnp` shapes:
//   - with Netid column:  "tcp LISTEN 0 128 0.0.0.0:8080 ..."
//   - without Netid:      "LISTEN 0 128 0.0.0.0:8080 ..."
func TestParseSSOutputFormats(t *testing.T) {
	const withNetid = `Netid State  Recv-Q Send-Q Local Address:Port  Peer Address:Port Process
tcp   LISTEN 0      128    0.0.0.0:8080         0.0.0.0:*      users:(("nginx",pid=123,fd=6))
tcp   LISTEN 0      128    [::]:9090               [::]:*         users:(("app",pid=456,fd=7))
tcp   LISTEN 0      128    127.0.0.1:5432         0.0.0.0:*      users:(("postgres",pid=789,fd=5))
`
	const withoutNetid = `State  Recv-Q Send-Q Local Address:Port  Peer Address:Port Process
LISTEN 0      128    0.0.0.0:8080         0.0.0.0:*      users:(("nginx",pid=123,fd=6))
LISTEN 0      128    [::]:9090               [::]:*         users:(("app",pid=456,fd=7))
`

	for name, out := range map[string]string{"with-netid": withNetid, "without-netid": withoutNetid} {
		res := parseSSOutput(out, 9999)
		if !res.V4Wild[8080] {
			t.Errorf("%s: expected V4Wild[8080]", name)
		}
		if !res.V6Any[9090] {
			t.Errorf("%s: expected V6Any[9090]", name)
		}
		if !res.V6Others[9090] {
			t.Errorf("%s: expected V6Others[9090] (pid 456 != 9999)", name)
		}
		if res.PIDs[8080] != 123 {
			t.Errorf("%s: expected PIDs[8080]=123, got %d", name, res.PIDs[8080])
		}
		if res.Names[8080] != "nginx" {
			t.Errorf("%s: expected Names[8080]=nginx, got %q", name, res.Names[8080])
		}
		// 127.0.0.1 is a specific bind, must not appear in wildcard maps.
		if res.V4Wild[5432] || res.V6Any[5432] {
			t.Errorf("%s: specific bind 127.0.0.1:5432 leaked into wildcard maps", name)
		}
	}

	// Own-process v6 listener must not be flagged as foreign.
	own := parseSSOutput("tcp LISTEN 0 128 [::]:8443 [::]:* users:((\"nasconnplus\",pid=42,fd=9))\n", 42)
	if !own.V6Any[8443] {
		t.Error("expected V6Any[8443]")
	}
	if own.V6Others[8443] {
		t.Error("own-process listener wrongly flagged V6Others")
	}

	// Malformed lines must be skipped, never panic.
	bad := "garbage\nLISTEN\nLISTEN 0\nLISTEN 0 128 not-an-addr 0.0.0.0:*\nLISTEN 0 128 0.0.0.0:0 0.0.0.0:*\nLISTEN 0 128 0.0.0.0:99999 0.0.0.0:*\n"
	res := parseSSOutput(bad, 1)
	if len(res.V4Wild) != 0 || len(res.V6Any) != 0 {
		t.Errorf("malformed input produced entries: %+v", res)
	}
}

func TestShouldRefreshInodesCooldown(t *testing.T) {
	old := inodeRefreshCooldown
	defer func() { inodeRefreshCooldown = old }()

	// Zero cooldown: every call refreshes (deterministic for tests).
	inodeRefreshCooldown = 0
	if !shouldRefreshInodes() {
		t.Fatal("expected refresh with zero cooldown")
	}
	if !shouldRefreshInodes() {
		t.Fatal("expected refresh on every call with zero cooldown")
	}

	// Long cooldown: second immediate call is debounced.
	inodeRefreshCooldown = time.Hour
	lastRefreshUnix.Store(time.Now().UnixNano())
	if shouldRefreshInodes() {
		t.Fatal("expected debounce with hour cooldown")
	}
}
