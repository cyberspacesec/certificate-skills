package display

import (
	"fmt"
	"os"
	"strings"
	"syscall"
	"unsafe"

	"github.com/charmbracelet/lipgloss"
)

// Color palette - a cyberpunk/hacker aesthetic for a security toolkit
var (
	// Brand colors
	primary   = lipgloss.Color("#00FF87") // Neon green - main accent
	secondary = lipgloss.Color("#00D4FF") // Cyan - secondary accent
	warning   = lipgloss.Color("#FFD700") // Gold - warnings
	danger    = lipgloss.Color("#FF4757") // Red - errors/critical
	success   = lipgloss.Color("#2ED573") // Green - success
	info      = lipgloss.Color("#70A1FF") // Blue - informational
	muted     = lipgloss.Color("#636E72") // Gray - muted text
	highlight = lipgloss.Color("#FF6B81") // Pink - highlight
	dim       = lipgloss.Color("#2D3436") // Dark gray - subtle

	// Text styles
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#FFFFFF")).
			Background(primary).
			Padding(0, 2)

	subtitleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(secondary)

	labelStyle = lipgloss.NewStyle().
			Foreground(muted)

	valueStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FFFFFF"))

	successStyle = lipgloss.NewStyle().
			Foreground(success).
			Bold(true)

	errorStyle = lipgloss.NewStyle().
			Foreground(danger).
			Bold(true)

	warningStyle = lipgloss.NewStyle().
			Foreground(warning).
			Bold(true)

	infoStyle = lipgloss.NewStyle().
			Foreground(info)

	criticalStyle = lipgloss.NewStyle().
			Foreground(danger).
			Bold(true)

	highStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FF6348")).
			Bold(true)

	mediumStyle = lipgloss.NewStyle().
			Foreground(warning)

	goodStyle = lipgloss.NewStyle().
			Foreground(success).
			Bold(true)

	// Box styles
	boxStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(primary).
			Padding(1, 2)

	warningBoxStyle = lipgloss.NewStyle().
				Border(lipgloss.RoundedBorder()).
				BorderForeground(warning).
				Padding(1, 2)

	errorBoxStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(danger).
			Padding(1, 2)

	// Section separator
	separatorStyle = lipgloss.NewStyle().
			Foreground(primary)

	// Item bullet
	bulletStyle = lipgloss.NewStyle().
			Foreground(primary)

	// Dimmed text
	dimStyle = lipgloss.NewStyle().
			Foreground(muted)
)

// Banner prints the cert-hacker ASCII art banner.
func Banner() {
	banner := `
  ██████╗██████╗ ███████╗ █████╗ ████████╗██╗  ██╗
 ██╔════╝██╔══██╗██╔════╝██╔══██╗╚══██╔══╝██║  ██║
 ██║     ██████╔╝█████╗  ███████║   ██║   ███████║
 ██║     ██╔══██╗██╔══╝  ██╔══██║   ██║   ██╔══██║
 ╚██████╗██║  ██║███████╗██║  ██║   ██║   ██║  ██║
  ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝`
	bannerStyled := lipgloss.NewStyle().
		Foreground(primary).
		Bold(true).
		Render(banner)

	tagline := lipgloss.NewStyle().
		Foreground(secondary).
		Italic(true).
		Render("  Certificate Security Toolkit for Cyberspace Mapping")

	fmt.Fprintln(os.Stderr, bannerStyled)
	fmt.Fprintln(os.Stderr, tagline)
	fmt.Fprintln(os.Stderr)
}

// Title renders a styled section title.
func Title(text string) string {
	return titleStyle.Render(" " + text + " ")
}

// Subtitle renders a styled subtitle.
func Subtitle(text string) string {
	return subtitleStyle.Render(text)
}

// Label renders a label (key) in muted color.
func Label(text string) string {
	return labelStyle.Render(text)
}

// Value renders a value in white.
func Value(text string) string {
	return valueStyle.Render(text)
}

// KeyValue renders a key: value pair with styled formatting.
func KeyValue(key, value string) string {
	return fmt.Sprintf("%s %s", labelStyle.Render(key+":"), valueStyle.Render(value))
}

// Success renders a success message with icon.
func Success(text string) string {
	return successStyle.Render("✓ " + text)
}

// Error renders an error message with icon.
func Error(text string) string {
	return errorStyle.Render("✗ " + text)
}

// Warning renders a warning message with icon.
func Warning(text string) string {
	return warningStyle.Render("⚠ " + text)
}

// Info renders an informational message with icon.
func Info(text string) string {
	return infoStyle.Render("ℹ " + text)
}

// Bullet renders a bullet point.
func Bullet(text string) string {
	return fmt.Sprintf("%s %s", bulletStyle.Render("▸"), valueStyle.Render(text))
}

// BulletKeyValue renders a bullet point with key: value.
func BulletKeyValue(key, value string) string {
	return fmt.Sprintf("%s %s %s", bulletStyle.Render("▸"), labelStyle.Render(key+":"), valueStyle.Render(value))
}

// Separator renders a horizontal separator line.
func Separator() string {
	width := getTermWidth()
	line := strings.Repeat("─", min(width, 60))
	return separatorStyle.Render(line)
}

// ThinSeparator renders a thin separator.
func ThinSeparator() string {
	width := getTermWidth()
	line := strings.Repeat("·", min(width, 60))
	return dimStyle.Render(line)
}

// Box renders content inside a styled box.
func Box(content string) string {
	return boxStyle.Render(content)
}

// WarningBox renders content inside a warning-styled box.
func WarningBox(content string) string {
	return warningBoxStyle.Render(content)
}

// ErrorBox renders content inside an error-styled box.
func ErrorBox(content string) string {
	return errorBoxStyle.Render(content)
}

// SeverityStyle returns the appropriate style for a severity level.
func SeverityStyle(severity string) string {
	switch strings.ToUpper(severity) {
	case "CRITICAL":
		return criticalStyle.Render("💀 CRITICAL")
	case "HIGH":
		return highStyle.Render("🚨 HIGH")
	case "MEDIUM":
		return mediumStyle.Render("⚠️  MEDIUM")
	case "GOOD":
		return goodStyle.Render("✅ GOOD")
	case "LOW":
		return mediumStyle.Render("🔸 LOW")
	case "INFO":
		return infoStyle.Render("ℹ️  INFO")
	default:
		return valueStyle.Render(severity)
	}
}

// ScoreStyle returns a colored score based on value.
func ScoreStyle(score int) string {
	var style lipgloss.Style
	switch {
	case score >= 80:
		style = goodStyle
	case score >= 50:
		style = mediumStyle
	case score >= 30:
		style = highStyle
	default:
		style = criticalStyle
	}

	// Create a visual score bar
	barWidth := 20
	filled := score * barWidth / 100
	bar := strings.Repeat("█", filled) + strings.Repeat("░", barWidth-filled)

	return fmt.Sprintf("%s %s %s", style.Render(fmt.Sprintf("%3d", score)), style.Render(bar), dimStyle.Render("/100"))
}

// BoolIcon returns a colored check/cross icon.
func BoolIcon(val bool) string {
	if val {
		return successStyle.Render("✅")
	}
	return errorStyle.Render("❌")
}

// StatusIcon returns a status-appropriate icon.
func StatusIcon(status string) string {
	switch strings.ToLower(status) {
	case "healthy", "good", "secure", "pass", "passed", "valid":
		return successStyle.Render("✅")
	case "warning", "medium":
		return warningStyle.Render("⚠️")
	case "critical", "high", "vulnerable", "fail", "failed", "expired":
		return criticalStyle.Render("🚨")
	case "error":
		return errorStyle.Render("❌")
	case "info", "low":
		return infoStyle.Render("ℹ️")
	default:
		return valueStyle.Render("•")
	}
}

// SectionHeader renders a prominent section header.
func SectionHeader(title string) string {
	width := getTermWidth()
	lineWidth := min(width, 60) - len(title) - 3
	if lineWidth < 3 {
		lineWidth = 3
	}
	line := strings.Repeat("─", lineWidth)
	return fmt.Sprintf("\n%s %s", titleStyle.Render(" "+title+" "), separatorStyle.Render(line))
}

// List renders a list of items with bullets.
func List(items []string) string {
	var lines []string
	for _, item := range items {
		lines = append(lines, Bullet(item))
	}
	return strings.Join(lines, "\n")
}

// ListKeyValue renders a list of key-value pairs.
func ListKeyValue(pairs [][2]string) string {
	var lines []string
	for _, pair := range pairs {
		lines = append(lines, BulletKeyValue(pair[0], pair[1]))
	}
	return strings.Join(lines, "\n")
}

// Dim renders dimmed/muted text.
func Dim(text string) string {
	return dimStyle.Render(text)
}

// Highlight renders highlighted text.
func Highlight(text string) string {
	return lipgloss.NewStyle().
		Foreground(highlight).
		Bold(true).
		Render(text)
}

// Header renders a styled header row for tables.
func Header(columns ...string) string {
	var styled []string
	for _, col := range columns {
		styled = append(styled, subtitleStyle.Bold(true).Render(col))
	}
	return strings.Join(styled, "  ")
}

// Row renders a table row.
func Row(columns ...string) string {
	return strings.Join(columns, "  ")
}

// PrintSection prints a named section with items.
func PrintSection(title string, items [][2]string) {
	fmt.Println(SectionHeader(title))
	for _, item := range items {
		fmt.Println(BulletKeyValue(item[0], item[1]))
	}
}

// PrintCheckResult prints a single check result with pass/fail styling.
func PrintCheckResult(name string, passed bool, detail string) {
	var icon string
	var nameStyle lipgloss.Style
	if passed {
		icon = successStyle.Render("✅")
		nameStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#DDDDDD"))
	} else {
		icon = errorStyle.Render("❌")
		nameStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#FF6B81")).Bold(true)
	}
	fmt.Printf("  %s %s %s\n", icon, nameStyle.Render(name), dimStyle.Render(detail))
}

// getTermWidth returns the terminal width, with a default fallback.
func getTermWidth() int {
	width := 80
	if w, _, err := termSize(); err == nil && w > 40 {
		width = w
	}
	return width
}

// termSize returns the terminal dimensions.
func termSize() (int, int, error) {
	return getTerminalSize(os.Stderr.Fd())
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// --- Terminal size detection ---

type winsize struct {
	Row    uint16
	Col    uint16
	Xpixel uint16
	Ypixel uint16
}

func getTerminalSize(fd uintptr) (int, int, error) {
	var ws winsize
	_, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL,
		fd,
		syscall.TIOCGWINSZ,
		uintptr(unsafe.Pointer(&ws)),
	)
	if errno != 0 {
		return 0, 0, fmt.Errorf("ioctl TIOCGWINSZ failed: %v", errno)
	}
	return int(ws.Col), int(ws.Row), nil
}
