package ipc

import (
	"encoding/json"
	"fmt"
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

// QueryStatus queries the running daemon through the Unix domain socket
func QueryStatus(socketPath string) (*StatusReport, error) {
	conn, err := net.DialTimeout("unix", socketPath, 2*time.Second)
	if err != nil {
		return nil, fmt.Errorf("connect to nasconnplus daemon at %s: %w (is the service running?)", socketPath, err)
	}
	defer conn.Close()

	var report StatusReport
	if err := json.NewDecoder(conn).Decode(&report); err != nil {
		return nil, fmt.Errorf("decode daemon response: %w", err)
	}

	return &report, nil
}

// RenderStatus formats the status report into an ergonomic Lipgloss dashboard table
func RenderStatus(report *StatusReport) string {
	if len(report.Listeners) == 0 {
		return "nasconn+ daemon is running, but no active proxy listeners are currently open."
	}

	var rows [][]string
	var totalActive int64
	var totalTraffic uint64

	now := time.Now()
	for _, l := range report.Listeners {
		totalActive += l.ActiveConn
		trafficBytes := l.BytesIn + l.BytesOut
		totalTraffic += trafficBytes

		typeStr := styleTypeRelay
		if l.Kind == "https" {
			typeStr = styleTypeHTTPS
		}

		activeStr := strconv.FormatInt(l.ActiveConn, 10)
		if l.ActiveConn > 0 {
			activeStr = styleActivePositive.Render(activeStr)
		}

		listenStr := fmt.Sprintf(":%d", l.Port)
		if l.Kind == "https" {
			listenStr = fmt.Sprintf("https :%d", l.Port)
		} else {
			listenStr = fmt.Sprintf("[::]:%d", l.Port)
		}

		trafficStr := fmt.Sprintf("↓ %s / ↑ %s", formatBytes(l.BytesIn), formatBytes(l.BytesOut))
		uptimeStr := formatDuration(now.Sub(l.StartedAt))

		rows = append(rows, []string{
			l.Name,
			typeStr,
			listenStr,
			fmt.Sprintf("127.0.0.1:%d", l.Backend),
			activeStr,
			strconv.FormatUint(l.TotalConn, 10),
			trafficStr,
			uptimeStr,
		})
	}

	t := table.New().
		Border(lipgloss.RoundedBorder()).
		BorderStyle(styleBorder).
		Headers("SERVICE", "TYPE", "LISTEN ADDR", "BACKEND", "ACTIVE", "TOTAL", "TRAFFIC (RX / TX)", "UPTIME").
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
		"● Daemon: v%s | Uptime: %s | Active Conns: %d | Total Traffic: %s",
		report.Version,
		daemonUptime,
		totalActive,
		formatBytes(totalTraffic),
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
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

func formatDuration(d time.Duration) string {
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
