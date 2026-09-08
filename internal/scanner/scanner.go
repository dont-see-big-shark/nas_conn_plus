package scanner

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dont-see-big-shark/nas_conn_plus/internal/tui"
)

var (
	pidRe  = regexp.MustCompile(`pid=(\d+)`)
	nameRe = regexp.MustCompile(`"([^"]+)"`)
)

// Result holds the classified listening ports from the host network
type Result struct {
	V4Wild   map[int]bool   // 0.0.0.0 wildcard listeners
	V6Any    map[int]bool   // [::] or * wildcard listeners (any process)
	V6Others map[int]bool   // [::] or * listeners owned by processes other than this binary
	PIDs     map[int]int    // port -> process PID
	Names    map[int]string // port -> process Name
}

// Scan queries local TCP listeners. It prefers reading Linux procfs directly for speed and zero dependencies,
// falling back to `ss -tlnp` on Linux, and `lsof` on macOS.
func Scan() (*Result, error) {
	// 1. Try reading Linux /proc/net/tcp and /proc/net/tcp6 (Zero dependency, high performance)
	if _, err := os.Stat("/proc/net/tcp"); err == nil {
		res, err := scanProcFS()
		if err == nil {
			return res, nil
		}
	}

	// 2. macOS fallback (for developer machine testing)
	if runtime.GOOS == "darwin" {
		return scanWithLsof()
	}

	// 3. Linux command fallback (`ss -tlnp`)
	return scanWithSS()
}

var (
	inodeMu      sync.RWMutex
	cachedInodes = make(map[string]procInfo)
)

func newResult() *Result {
	return &Result{
		V4Wild:   make(map[int]bool),
		V6Any:    make(map[int]bool),
		V6Others: make(map[int]bool),
		PIDs:     make(map[int]int),
		Names:    make(map[int]string),
	}
}

func getSelfSocketInodesWith(fdDir string) map[string]bool {
	inodes := make(map[string]bool)
	fds, err := os.ReadDir(filepath.Clean(fdDir))
	if err != nil {
		return inodes
	}
	for _, fd := range fds {
		target, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
		if err != nil {
			continue
		}
		if strings.HasPrefix(target, "socket:[") && strings.HasSuffix(target, "]") {
			inode := target[8 : len(target)-1]
			inodes[inode] = true
		}
	}
	return inodes
}

func scanProcFS() (*Result, error) {
	return scanProcFSWith("/proc", "/proc/self/fd")
}

func lookupProcInfo(inode string) (procInfo, bool) {
	inodeMu.RLock()
	defer inodeMu.RUnlock()
	info, ok := cachedInodes[inode]
	return info, ok
}

var lastRefreshUnix atomic.Int64

// inodeRefreshCooldown debounces full /proc inode rescans. Tests may set it
// to 0 for deterministic refresh; production keeps 10s to bound readlink cost.
var inodeRefreshCooldown = 10 * time.Second

func shouldRefreshInodes() bool {
	now := time.Now()
	last := time.Unix(0, lastRefreshUnix.Load())
	if now.Sub(last) < inodeRefreshCooldown {
		return false
	}
	return lastRefreshUnix.CompareAndSwap(last.UnixNano(), now.UnixNano())
}

func scanProcFSWith(procRoot, selfFdDir string) (*Result, error) {
	mypid := os.Getpid()
	selfInodes := getSelfSocketInodesWith(selfFdDir)

	res := newResult()

	// First pass uses per-inode RLock lookups, no full-map copy (P1 perf).
	missingInodes := false
	lookup := func(inode string) (procInfo, bool) { return lookupProcInfo(inode) }

	tcpPath := filepath.Join(procRoot, "net/tcp")
	tcp6Path := filepath.Join(procRoot, "net/tcp6")

	if err := parseProcNetFileLookup(tcpPath, false, res, mypid, selfInodes, lookup, &missingInodes); err != nil {
		return nil, err
	}
	if err := parseProcNetFileLookup(tcp6Path, true, res, mypid, selfInodes, lookup, &missingInodes); err != nil {
		return nil, err
	}

	// If new sockets appeared that weren't in our cache, refresh cache (debounced) and re-populate.
	if missingInodes && shouldRefreshInodes() {
		inodeMap := refreshInodeCacheWith(procRoot)
		res = newResult()
		lookup2 := func(inode string) (procInfo, bool) {
			info, ok := inodeMap[inode]
			return info, ok
		}
		if err := parseProcNetFileLookup(tcpPath, false, res, mypid, selfInodes, lookup2, nil); err != nil {
			return nil, err
		}
		if err := parseProcNetFileLookup(tcp6Path, true, res, mypid, selfInodes, lookup2, nil); err != nil {
			return nil, err
		}
	}

	return res, nil
}

type procInfo struct {
	pid  int
	name string
}

//nolint:unused // test helper used by scanner_test (linter runs with tests:false).
func parseProcNetFile(path string, isV6 bool, res *Result, mypid int, selfInodes map[string]bool, inodeMap map[string]procInfo, missingInodes *bool) error {
	lookup := func(inode string) (procInfo, bool) {
		info, ok := inodeMap[inode]
		return info, ok
	}
	return parseProcNetFileInner(path, isV6, res, mypid, selfInodes, lookup, missingInodes)
}

//nolint:unused // read helper used by scanner_test (linter runs with tests:false).
func getCachedInodes() map[string]procInfo {
	inodeMu.RLock()
	defer inodeMu.RUnlock()
	copyMap := make(map[string]procInfo, len(cachedInodes))
	for k, v := range cachedInodes {
		copyMap[k] = v
	}
	return copyMap
}

func refreshInodeCacheWith(procRoot string) map[string]procInfo {
	newMap := buildInodeToPIDMapWith(procRoot)
	inodeMu.Lock()
	cachedInodes = newMap
	inodeMu.Unlock()
	return newMap
}

func buildInodeToPIDMapWith(procRoot string) map[string]procInfo {
	inodes := make(map[string]procInfo)
	procDirs, err := os.ReadDir(filepath.Clean(procRoot))
	if err != nil {
		return inodes
	}

	for _, d := range procDirs {
		if !d.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(d.Name())
		if err != nil {
			continue
		}

		// Read process name from /proc/[pid]/comm
		pName := ""
		// #nosec G304 - procRoot is bounded
		if commBytes, err := os.ReadFile(filepath.Join(procRoot, d.Name(), "comm")); err == nil {
			pName = strings.TrimSpace(string(commBytes))
		}

		fdDir := filepath.Join(procRoot, d.Name(), "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}

		for _, fd := range fds {
			target, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil {
				continue
			}
			if strings.HasPrefix(target, "socket:[") && strings.HasSuffix(target, "]") {
				inode := target[8 : len(target)-1]
				inodes[inode] = procInfo{pid: pid, name: pName}
			}
		}
	}

	return inodes
}

// parseProcNetFile parses /proc/net/tcp{,6} and populates res.
// P1-2 fix: uses socketPID directly (not res.PIDs[port] which would be stale from
// the opposite address family pass) and respects selfInodes so our own [::] sockets
// never set V6Others. On missingInodes double-parse, caller provides a fresh
// newResult() so stale V6Others cannot persist.
func parseProcNetFileLookup(path string, isV6 bool, res *Result, mypid int, selfInodes map[string]bool, lookup func(string) (procInfo, bool), missingInodes *bool) error {
	// lookup-based fast path (no map copy)
	return parseProcNetFileInner(path, isV6, res, mypid, selfInodes, lookup, missingInodes)
}

func parseProcNetFileInner(path string, isV6 bool, res *Result, mypid int, selfInodes map[string]bool, lookup func(string) (procInfo, bool), missingInodes *bool) error {
	// #nosec G304 - path is restricted to /proc/net/tcp or /proc/net/tcp6
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		if os.IsNotExist(err) && isV6 {
			return nil
		}
		return err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	// Skip header line
	if !sc.Scan() {
		return sc.Err()
	}

	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 10 {
			continue
		}

		// TCP state 0A is TCP_LISTEN
		state := fields[3]
		if state != "0A" {
			continue
		}

		localAddr := fields[1]
		parts := strings.Split(localAddr, ":")
		if len(parts) != 2 {
			continue
		}

		portHex := parts[1]
		portUint, err := strconv.ParseUint(portHex, 16, 32)
		if err != nil || portUint == 0 || portUint > 65535 {
			continue
		}
		port := int(portUint)

		inode := fields[9]
		isSelfSocket := selfInodes != nil && selfInodes[inode]

		if isSelfSocket {
			res.PIDs[port] = mypid
			res.Names[port] = "nasconnplus"
		} else if info, ok := lookup(inode); ok {
			res.PIDs[port] = info.pid
			res.Names[port] = info.name
		} else if missingInodes != nil {
			*missingInodes = true
		}

		ipHex := strings.ToUpper(parts[0])

		if !isV6 {
			// IPv4: 00000000 represents 0.0.0.0
			if ipHex == "00000000" {
				res.V4Wild[port] = true
			}
		} else {
			switch ipHex {
			case "00000000000000000000000000000000":
				res.V6Any[port] = true
				if !isSelfSocket {
					// Socket does not belong to our process -> external dual-stack or v6 listener
					res.V6Others[port] = true
				}
			case "00000000000000000000FFFF00000000":
				res.V4Wild[port] = true
			}
		}
	}

	return sc.Err()
}

func scanWithSS() (*Result, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "ss", "-tlnp")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("execute ss -tlnp: %w: %s", err, strings.TrimSpace(string(out)))
	}

	return parseSSOutput(string(out), os.Getpid()), nil
}

func parseSSOutput(out string, mypid int) *Result {
	res := &Result{
		V4Wild:   make(map[int]bool),
		V6Any:    make(map[int]bool),
		V6Others: make(map[int]bool),
		PIDs:     make(map[int]int),
		Names:    make(map[int]string),
	}

	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		// P0-3 FIX: `ss -tlnp` output shape differs by version. Some builds
		// print a leading Netid column ("tcp LISTEN ..."), others start at
		// State ("LISTEN ..."). Locate the STATE column instead of assuming
		// fields[0], and take Local = STATE+3
		// (State Recv-Q Send-Q Local Peer ...).
		stateIdx := -1
		for i, f := range fields {
			if f == "LISTEN" {
				stateIdx = i
				break
			}
		}
		if stateIdx < 0 || stateIdx+3 >= len(fields) {
			continue
		}

		local := fields[stateIdx+3]
		if !strings.Contains(local, ":") {
			continue
		}
		idx := strings.LastIndex(local, ":")
		if idx < 0 {
			continue
		}

		addr := local[:idx]
		port, err := strconv.Atoi(local[idx+1:])
		if err != nil || port <= 0 || port > 65535 {
			continue
		}

		pid := 0
		if m := pidRe.FindStringSubmatch(line); len(m) > 1 {
			pid, _ = strconv.Atoi(m[1])
			res.PIDs[port] = pid
		}

		if m := nameRe.FindStringSubmatch(line); len(m) > 1 {
			res.Names[port] = m[1]
		}

		switch addr {
		case "0.0.0.0":
			res.V4Wild[port] = true
		case "*", "[::]":
			res.V6Any[port] = true
			if pid != mypid {
				res.V6Others[port] = true
			}
		}
	}

	return res
}

func scanWithLsof() (*Result, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "lsof", "-iTCP", "-sTCP:LISTEN", "-n", "-P")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("execute lsof: %w: %s", err, strings.TrimSpace(string(out)))
	}

	mypid := os.Getpid()
	res := &Result{
		V4Wild:   make(map[int]bool),
		V6Any:    make(map[int]bool),
		V6Others: make(map[int]bool),
		PIDs:     make(map[int]int),
		Names:    make(map[int]string),
	}

	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		// Expected format: COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME(e.g. *:5000 (LISTEN))
		if len(fields) < 9 || !strings.Contains(line, "(LISTEN)") {
			continue
		}

		pName := fields[0]
		pid, _ := strconv.Atoi(fields[1])
		ipType := fields[4] // IPv4 or IPv6
		nameField := fields[8]

		idx := strings.LastIndex(nameField, ":")
		if idx < 0 {
			continue
		}

		addr := nameField[:idx]
		port, err := strconv.Atoi(nameField[idx+1:])
		if err != nil || port <= 0 || port > 65535 {
			continue
		}

		res.PIDs[port] = pid
		res.Names[port] = pName

		if addr == "*" || addr == "0.0.0.0" {
			if ipType == "IPv4" {
				res.V4Wild[port] = true
			}
		}
		if addr == "*" || addr == "[::]" {
			if ipType == "IPv6" {
				res.V6Any[port] = true
				if pid != mypid {
					res.V6Others[port] = true
				}
			}
		}
	}

	return res, nil
}

type DiagnosticOptions struct {
	ExcludedPorts []int
	HTTPSAuto     bool
	HTTPSOffset   int
	HTTPSMode     string
	HTTPSAllow    []int
}

func httpsAutoAllowed(backend int, opts DiagnosticOptions) bool {
	if opts.HTTPSMode == "whitelist" {
		if len(opts.HTTPSAllow) == 0 {
			return false
		}
		for _, p := range opts.HTTPSAllow {
			if p == backend {
				return true
			}
		}
		return false
	}
	if len(opts.HTTPSAllow) == 0 {
		return true
	}
	for _, p := range opts.HTTPSAllow {
		if p == backend {
			return true
		}
	}
	return false
}

func (r *Result) DiagnosticReport(opts DiagnosticOptions) string {
	excludeMap := make(map[int]bool)
	for _, p := range opts.ExcludedPorts {
		excludeMap[p] = true
	}

	allPortsMap := make(map[int]bool)
	for p := range r.V4Wild {
		allPortsMap[p] = true
	}
	for p := range r.V6Any {
		allPortsMap[p] = true
	}

	var ports []int
	for p := range allPortsMap {
		ports = append(ports, p)
	}
	sort.Ints(ports)

	if len(ports) == 0 {
		return "No listening TCP wildcard ports detected."
	}

	// P1/P2: pre-probe in parallel with bounded concurrency instead of sequential blocking.
	var httpPred map[int]bool
	{
		toProbe := make([]int, 0, len(ports))
		for _, p := range ports {
			if !excludeMap[p] && (r.V4Wild[p] || r.V6Any[p]) {
				toProbe = append(toProbe, p)
			}
		}
		httpPred = ProbePorts(toProbe)
	}

	var rows [][]string
	for _, p := range ports {
		v4 := r.V4Wild[p]
		v6 := r.V6Any[p]
		pidStr := "-"
		if pid, ok := r.PIDs[p]; ok && pid > 0 {
			pidStr = strconv.Itoa(pid)
		}
		pName := r.Names[p]
		if pName == "" {
			pName = "-"
		}

		action := tui.RelayAction(excludeMap[p], v4, v6)

		v4Str := tui.BoolBadge(v4)
		v6Str := tui.BoolBadge(v6)

		httpsPred := "-"
		if excludeMap[p] {
			httpsPred = tui.ExcludedBadge()
		} else if v4 || v6 {
			if !httpPred[p] {
				httpsPred = tui.NoHTTP()
			} else if !opts.HTTPSAuto {
				httpsPred = tui.HTTPSAutoDisabled()
			} else if httpsAutoAllowed(p, opts) {
				target := p + opts.HTTPSOffset
				if opts.HTTPSOffset <= 0 {
					target = p + 1
				}
				if target > 65535 {
					httpsPred = tui.HTTPSRange()
				} else {
					httpsPred = tui.HTTPSReadyAt(target)
				}
			} else {
				httpsPred = tui.ExcludedBadge()
			}
		}

		rows = append(rows, []string{
			strconv.Itoa(p),
			v4Str,
			v6Str,
			pidStr,
			pName,
			action,
			httpsPred,
		})
	}

	return renderDiagnosticTable(rows, opts.HTTPSOffset)
}

func renderDiagnosticTable(rows [][]string, httpsOffset int) string {
	return tui.RenderTable([]string{
		"PORT", "IPv4 (0.0.0.0)", "IPv6 ([::])", "PID", "PROCESS", "RELAY ACTION",
		fmt.Sprintf("HTTPS (+%d)", max(1, httpsOffset)),
	}, rows)
}
