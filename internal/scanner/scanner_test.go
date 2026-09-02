package scanner

import (
	"os"
	"strings"
	"testing"
)

func TestDiagnosticReport(t *testing.T) {
	res := &Result{
		V4Wild:   map[int]bool{8080: true, 22: true},
		V6Any:    map[int]bool{22: true, 9090: true},
		V6Others: map[int]bool{22: true},
		PIDs:     map[int]int{8080: 1234, 22: 100},
		Names:    map[int]string{8080: "web", 22: "sshd"},
	}

	report := res.DiagnosticReport([]int{53})
	if !strings.Contains(report, "8080") {
		t.Errorf("expected report to contain port 8080, got:\n%s", report)
	}
	if !strings.Contains(report, "Will Relay") {
		t.Errorf("expected report to contain 'Will Relay', got:\n%s", report)
	}
	if !strings.Contains(report, "Native Dual-Stack") {
		t.Errorf("expected report to contain 'Native Dual-Stack', got:\n%s", report)
	}
}

func TestParseProcNetFile(t *testing.T) {
	content := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode                                                     
   0: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0                     
   1: 0100007F:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 67890 1 0000000000000000 100 0 0 10 0                     
   2: 00000000:1F90 00000000:0000 01 00000000:00000000 00:00000000 00000000     0        0 99999 1 0000000000000000 100 0 0 10 0                     
`
	tmpFile, err := os.CreateTemp("", "proc_net_tcp_*")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(content); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}
	tmpFile.Close()

	res := &Result{
		V4Wild:   make(map[int]bool),
		V6Any:    make(map[int]bool),
		V6Others: make(map[int]bool),
		PIDs:     make(map[int]int),
		Names:    make(map[int]string),
	}
	inodeMap := map[string]procInfo{
		"12345": {pid: 1000, name: "nginx"},
	}
	var missingInodes bool

	if err := parseProcNetFile(tmpFile.Name(), false, res, 9999, inodeMap, &missingInodes); err != nil {
		t.Fatalf("parseProcNetFile failed: %v", err)
	}

	// 0x50 = 80
	if !res.V4Wild[80] {
		t.Errorf("expected port 80 in V4Wild")
	}
	if res.PIDs[80] != 1000 || res.Names[80] != "nginx" {
		t.Errorf("expected pid 1000 and name nginx for port 80, got %d %s", res.PIDs[80], res.Names[80])
	}
	// 0x16 = 22, bound to 127.0.0.1, not wildcard
	if res.V4Wild[22] {
		t.Errorf("expected port 22 not in V4Wild")
	}
	// missingInodes should be true because inode 67890 was not in inodeMap
	if !missingInodes {
		t.Errorf("expected missingInodes to be true for unmapped socket")
	}
}

