package logger

import (
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/charmbracelet/lipgloss"
)

type Logger struct {
	mu       sync.Mutex
	out      io.Writer
	useColor bool

	tagInfo   string
	tagAdd    string
	tagStop   string
	tagReload string
	tagWarn   string
	timeStyle lipgloss.Style
}

// New creates a new Logger with modern lipgloss styling.
func New() *Logger {
	noColor := os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb"
	useColor := !noColor

	l := &Logger{
		out:      os.Stdout,
		useColor: useColor,
	}

	if useColor {
		l.tagInfo = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#8BE9FD")).Render("[INFO]")
		l.tagAdd = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#50FA7B")).Render("[ + ]")
		l.tagStop = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FFB86C")).Render("[ - ]")
		l.tagReload = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#BD93F9")).Render("[ ~ ]")
		l.tagWarn = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FF5555")).Render("[ ! ]")
		l.timeStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#6272A4"))
	} else {
		l.tagInfo = "[INFO]"
		l.tagAdd = "[ + ]"
		l.tagStop = "[ - ]"
		l.tagReload = "[ ~ ]"
		l.tagWarn = "[ ! ]"
	}

	return l
}

func (l *Logger) logf(renderedTag, format string, args ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now().Format("2006-01-02 15:04:05")
	msg := fmt.Sprintf(format, args...)

	if l.useColor {
		fmt.Fprintf(l.out, "%s %s %s\n", l.timeStyle.Render(now), renderedTag, msg)
	} else {
		fmt.Fprintf(l.out, "%s %s %s\n", now, renderedTag, msg)
	}
}

// Info logs general informational messages
func (l *Logger) Info(format string, args ...interface{}) {
	l.logf(l.tagInfo, format, args...)
}

// Add logs when a new listener is established
func (l *Logger) Add(format string, args ...interface{}) {
	l.logf(l.tagAdd, format, args...)
}

// Stop logs when a listener is removed
func (l *Logger) Stop(format string, args ...interface{}) {
	l.logf(l.tagStop, format, args...)
}

// Reload logs configuration or certificate reloads
func (l *Logger) Reload(format string, args ...interface{}) {
	l.logf(l.tagReload, format, args...)
}

// Warn logs warnings or conflicts
func (l *Logger) Warn(format string, args ...interface{}) {
	l.logf(l.tagWarn, format, args...)
}

// Banner prints a stylized startup header
func (l *Logger) Banner(version string) {
	bannerText := `
  _  _   _   ___  ___ ___  _  _ _  _     _ 
 | \| | /_\ / __|/ __/ _ \| \| | \| |___| |
 | .` + "`" + ` |/ _ \\__ \ (_| (_) | .` + "`" + ` | .` + "`" + ` |___|_|
 |_|\_/_/ \_\___/\___\___/|_|\_|_|\_|   (_)
`
	if l.useColor {
		logo := lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#00D7D7")).
			Render(bannerText)

		subtitle := lipgloss.NewStyle().
			Foreground(lipgloss.Color("#F8F8F2")).
			Bold(true).
			Render(fmt.Sprintf("   nasconn+ v%s", version))

		desc := lipgloss.NewStyle().
			Foreground(lipgloss.Color("#6272A4")).
			Render(" — Seamless IPv6 Relay & HTTPS Upgrade for NAS\n")

		fmt.Println(logo)
		fmt.Println(subtitle + desc)
	} else {
		fmt.Println(bannerText)
		fmt.Printf("   nasconn+ v%s — Seamless IPv6 Relay & HTTPS Upgrade for NAS\n\n", version)
	}
}
