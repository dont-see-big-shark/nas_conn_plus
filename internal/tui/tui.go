package tui

import (
	"fmt"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/lipgloss/table"
)

var (
	StyleHeader = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#00D7D7")).Padding(0, 1)
	StyleBorder = lipgloss.NewStyle().Foreground(lipgloss.Color("#6272A4"))
)

// RenderTable renders a generic bordered table. Scanner builds rows, tui owns styling.
func RenderTable(headers []string, rows [][]string) string {
	t := table.New().
		Border(lipgloss.RoundedBorder()).
		BorderStyle(StyleBorder).
		Headers(headers...).
		Rows(rows...).
		StyleFunc(func(row, col int) lipgloss.Style {
			if row == table.HeaderRow {
				return StyleHeader
			}
			return lipgloss.NewStyle().Padding(0, 1)
		})
	return t.Render()
}

var (
	badgeRelay     = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#50FA7B")).Render("● Will Relay to IPv6")
	badgeDualStack = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#8BE9FD")).Render("● Native Dual-Stack")
	badgeExcluded  = lipgloss.NewStyle().Foreground(lipgloss.Color("#6272A4")).Render("○ Excluded (Skip)")
	badgeV6Only    = lipgloss.NewStyle().Foreground(lipgloss.Color("#BD93F9")).Render("○ IPv6-Only")
	badgeYes       = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#50FA7B")).Render("YES")
	badgeNo        = lipgloss.NewStyle().Foreground(lipgloss.Color("#6272A4")).Render("No")
	badgeNoHTTP    = lipgloss.NewStyle().Foreground(lipgloss.Color("#6272A4")).Render("No HTTP")
	badgeAutoOff   = lipgloss.NewStyle().Foreground(lipgloss.Color("#6272A4")).Render("○ HTTPS Auto Off")
)

// Relay action badges. Scanner passes plain state, tui owns all styling.
func RelayBadge() string        { return badgeRelay }
func DualStackBadge() string    { return badgeDualStack }
func ExcludedBadge() string     { return badgeExcluded }
func V6OnlyBadge() string       { return badgeV6Only }
func Yes() string               { return badgeYes }
func No() string                { return badgeNo }
func NoHTTP() string            { return badgeNoHTTP }
func HTTPSAutoDisabled() string { return badgeAutoOff }
func HTTPSRange() string {
	return lipgloss.NewStyle().Foreground(lipgloss.Color("#FFB86C")).Render("○ > 65535")
}

// HTTPSReadyAt renders the configured port upgrade prediction for an HTTP backend.
func HTTPSReadyAt(target int) string {
	return lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#50FA7B")).Render(fmt.Sprintf("✓ https :%d", target))
}

// HTTPSReady renders the default +1 upgrade prediction for an HTTP backend.
func HTTPSReady(port int) string {
	return HTTPSReadyAt(port + 1)
}

// RelayAction classifies a port for display: excluded > relay > dual > v6only > none.
func RelayAction(excluded, v4, v6 bool) string {
	switch {
	case excluded:
		return badgeExcluded
	case v4 && !v6:
		return badgeRelay
	case v4 && v6:
		return badgeDualStack
	case !v4 && v6:
		return badgeV6Only
	default:
		return "-"
	}
}

// BoolBadge renders YES/No.
func BoolBadge(v bool) string {
	if v {
		return badgeYes
	}
	return badgeNo
}
