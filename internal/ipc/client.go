package ipc

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/lipgloss/table"
)

var (
	styleHeader = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#00D7D7")).
			Padding(0, 1)

	styleBorder = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#6272A4"))

	styleTypeHTTPS = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FF79C6")).
			Render("HTTPS (L7)")

	styleTypeRelay = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#8BE9FD")).
			Render("Relay (L4)")

	styleActivePositive = lipgloss.NewStyle().
				Bold(true).
				Foreground(lipgloss.Color("#50FA7B"))

	styleSummary = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#F8F8F2")).
			Bold(true)
)

// QueryStatus queries the running daemon through the Unix domain socket with timeout and size bounds
func QueryStatus(socketPath string) (*StatusReport, error) {
	conn, err := net.DialTimeout("unix", socketPath, 3*time.Second)
	if err != nil {
		return nil, fmt.Errorf("connect to nasconnplus daemon at %s: %w (is the service running?)", socketPath, err)
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	// Limit response reading to 1MB to protect against malformed or unbounded responses
	limitReader := io.LimitReader(conn, 1<<20)

	var report StatusReport
	if err := json.NewDecoder(limitReader).Decode(&report); err != nil {
		return nil, fmt.Errorf("decode daemon response: %w", err)
	}

	return &report, nil
}

// sanitizeString removes ANSI escape codes and ASCII control characters to prevent terminal injection
func sanitizeString(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 32 && r != 127 {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// truncateRunes caps attacker-influenced fields so a 1MB socket payload can't
// turn the status table into a terminal flood. Width is in runes, not bytes.
func truncateRunes(s string, max int) string {
	if max <= 0 {
		return ""
	}
	i := 0
	for idx := range s {
		if i == max {
			return s[:idx] + "…"
		}
		i++
	}
	return s
}

// RenderStatus formats the status report into an ergonomic Lipgloss dashboard table
func RenderStatus(report *StatusReport) string {
	if len(report.Listeners) == 0 {
		return "nasconn+ daemon is running, but no active proxy listeners are currently open."
	}

	var rows [][]string
	var totalActive int64
	var totalTraffic uint64
	var totalErrors uint64

	now := time.Now()
	for _, l := range report.Listeners {
		totalActive += l.ActiveConn
		trafficBytes := l.BytesIn + l.BytesOut
		totalTraffic += trafficBytes
		totalErrors += l.ErrorCount

		typeStr := styleTypeRelay
		if l.Kind == "https" {
			typeStr = styleTypeHTTPS
		}

		statusStr := lipgloss.NewStyle().Foreground(lipgloss.Color("#50FA7B")).Render("● OK")
		if l.ErrorCount > 0 {
			statusStr = lipgloss.NewStyle().Foreground(lipgloss.Color("#FF5555")).Render(fmt.Sprintf("▲ %d err", l.ErrorCount))
		}

		activeStr := strconv.FormatInt(l.ActiveConn, 10)
		if l.ActiveConn > 0 {
			activeStr = styleActivePositive.Render(activeStr)
		}

		var listenStr string
		if l.Kind == "https" {
			listenStr = fmt.Sprintf("https :%d", l.Port)
		} else {
			listenStr = fmt.Sprintf("[::]:%d", l.Port)
		}

		trafficStr := fmt.Sprintf("↓ %s / ↑ %s", formatBytes(l.BytesIn), formatBytes(l.BytesOut))
		uptimeStr := formatDuration(now.Sub(l.StartedAt))

		cleanName := truncateRunes(sanitizeString(l.Name), 48)

		rows = append(rows, []string{
			cleanName,
			typeStr,
			listenStr,
			fmt.Sprintf("127.0.0.1:%d", l.Backend),
			statusStr,
			activeStr,
			strconv.FormatUint(l.TotalConn, 10),
			trafficStr,
			uptimeStr,
		})
	}

	t := table.New().
		Border(lipgloss.RoundedBorder()).
		BorderStyle(styleBorder).
		Headers("SERVICE", "TYPE", "LISTEN ADDR", "BACKEND", "STATUS", "ACTIVE", "TOTAL", "TRAFFIC (RX / TX)", "UPTIME").
		Rows(rows...).
		StyleFunc(func(row, col int) lipgloss.Style {
			if row == table.HeaderRow {
				return styleHeader
			}
			return lipgloss.NewStyle().Padding(0, 1)
		})

	var sb strings.Builder
	sb.WriteString(t.Render())
	sb.WriteString("\n\n")

	daemonUptime := formatDuration(time.Duration(report.UptimeSeconds) * time.Second)
	summaryLine := fmt.Sprintf(
		"● Daemon: v%s | Uptime: %s | Active Conns: %d | Total Traffic: %s | Total Errors: %d",
		truncateRunes(sanitizeString(report.Version), 32),
		daemonUptime,
		totalActive,
		formatBytes(totalTraffic),
		totalErrors,
	)
	sb.WriteString(styleSummary.Render(summaryLine))

	return sb.String()
}

func formatBytes(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit && exp < 5; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

func formatDuration(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	d = d.Round(time.Second)
	days := d / (24 * time.Hour)
	d -= days * 24 * time.Hour
	hours := d / time.Hour
	d -= hours * time.Hour
	minutes := d / time.Minute
	d -= minutes * time.Minute
	seconds := d / time.Second

	if days > 0 {
		return fmt.Sprintf("%dd %02dh %02dm", days, hours, minutes)
	}
	if hours > 0 {
		return fmt.Sprintf("%dh %02dm %02ds", hours, minutes, seconds)
	}
	if minutes > 0 {
		return fmt.Sprintf("%dm %02ds", minutes, seconds)
	}
	return fmt.Sprintf("%ds", seconds)
}
