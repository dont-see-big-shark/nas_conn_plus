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
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/lipgloss/table"
)

var (
	pidRe  = regexp.MustCompile(`pid=(\d+)`)
	nameRe = regexp.MustCompile(`"([^"]+)"`)

	// Lipgloss styles for terminal aesthetics
	styleHeader = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#00D7D7")).
			Padding(0, 1)

	styleBorder = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#6272A4"))

	styleRelayBadge = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#50FA7B")).
			Render("● Will Relay to IPv6")

	styleDualStackBadge = lipgloss.NewStyle().
				Bold(true).
				Foreground(lipgloss.Color("#8BE9FD")).
				Render("● Native Dual-Stack")

	styleExcludedBadge = lipgloss.NewStyle().
				Foreground(lipgloss.Color("#6272A4")).
				Render("○ Excluded (Skip)")

	styleV6OnlyBadge = lipgloss.NewStyle().
				Foreground(lipgloss.Color("#BD93F9")).
				Render("○ IPv6-Only")

	styleYes = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#50FA7B")).
			Render("YES")

	styleNo = lipgloss.NewStyle().
		Foreground(lipgloss.Color("#6272A4")).
		Render("No")
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

func scanProcFS() (*Result, error) {
	mypid := os.Getpid()

	res := &Result{
		V4Wild:   make(map[int]bool),
		V6Any:    make(map[int]bool),
		V6Others: make(map[int]bool),
		PIDs:     make(map[int]int),
		Names:    make(map[int]string),
	}

	// First pass using cached inodes
	missingInodes := false
	inodeMap := getCachedInodes()

	if err := parseProcNetFile("/proc/net/tcp", false, res, mypid, inodeMap, &missingInodes); err != nil {
		return nil, err
	}
	if err := parseProcNetFile("/proc/net/tcp6", true, res, mypid, inodeMap, &missingInodes); err != nil {
		return nil, err
	}

	// If new sockets appeared that weren't in our cache, refresh cache and re-populate
	if missingInodes {
		inodeMap = refreshInodeCache()
		if err := parseProcNetFile("/proc/net/tcp", false, res, mypid, inodeMap, nil); err != nil {
			return nil, err
		}
		if err := parseProcNetFile("/proc/net/tcp6", true, res, mypid, inodeMap, nil); err != nil {
			return nil, err
		}
	}

	return res, nil
}

type procInfo struct {
	pid  int
	name string
}

func getCachedInodes() map[string]procInfo {
	inodeMu.RLock()
	defer inodeMu.RUnlock()
	copyMap := make(map[string]procInfo, len(cachedInodes))
	for k, v := range cachedInodes {
		copyMap[k] = v
	}
	return copyMap
}

func refreshInodeCache() map[string]procInfo {
	newMap := buildInodeToPIDMap()
	inodeMu.Lock()
	cachedInodes = newMap
	inodeMu.Unlock()
	return newMap
}

func buildInodeToPIDMap() map[string]procInfo {
	inodes := make(map[string]procInfo)
	procDirs, err := os.ReadDir("/proc")
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
		if commBytes, err := os.ReadFile(filepath.Join("/proc", d.Name(), "comm")); err == nil {
			pName = strings.TrimSpace(string(commBytes))
		}

		fdDir := filepath.Join("/proc", d.Name(), "fd")
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

func parseProcNetFile(path string, isV6 bool, res *Result, mypid int, inodeMap map[string]procInfo, missingInodes *bool) error {
	f, err := os.Open(path)
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
		if info, ok := inodeMap[inode]; ok {
			res.PIDs[port] = info.pid
			res.Names[port] = info.name
		} else if missingInodes != nil {
			*missingInodes = true
		}

		pid := res.PIDs[port]
		ipHex := parts[0]

		if !isV6 {
			// IPv4: 00000000 represents 0.0.0.0
			if ipHex == "00000000" {
				res.V4Wild[port] = true
			}
		} else {
			// IPv6: 00000000000000000000000000000000 represents [::]
			if ipHex == "00000000000000000000000000000000" {
				res.V6Any[port] = true
				if pid != mypid {
					res.V6Others[port] = true
				}
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
		if len(fields) < 4 || fields[0] != "LISTEN" {
			continue
		}

		local := fields[3]
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

		switch {
		case addr == "0.0.0.0":
			res.V4Wild[port] = true
		case addr == "*" || addr == "[::]":
			res.V6Any[port] = true
			if pid != mypid {
				res.V6Others[port] = true
			}
		}
	}

	return res, nil
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

// DiagnosticReport generates an attractive terminal report using charmbracelet/lipgloss/table
func (r *Result) DiagnosticReport(excludedPorts []int) string {
	excludeMap := make(map[int]bool)
	for _, p := range excludedPorts {
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

		var action string
		switch {
		case excludeMap[p]:
			action = styleExcludedBadge
		case v4 && !v6:
			action = styleRelayBadge
		case v4 && v6:
			action = styleDualStackBadge
		case !v4 && v6:
			action = styleV6OnlyBadge
		default:
			action = "-"
		}

		v4Str := styleNo
		if v4 {
			v4Str = styleYes
		}
		v6Str := styleNo
		if v6 {
			v6Str = styleYes
		}

		rows = append(rows, []string{
			strconv.Itoa(p),
			v4Str,
			v6Str,
			pidStr,
			pName,
			action,
		})
	}

	t := table.New().
		Border(lipgloss.RoundedBorder()).
		BorderStyle(styleBorder).
		Headers("PORT", "IPv4 (0.0.0.0)", "IPv6 ([::])", "PID", "PROCESS", "RELAY ACTION").
		Rows(rows...).
		StyleFunc(func(row, col int) lipgloss.Style {
			if row == table.HeaderRow {
				return styleHeader
			}
			return lipgloss.NewStyle().Padding(0, 1)
		})

	return t.Render()
}
