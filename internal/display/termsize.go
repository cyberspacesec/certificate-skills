package display

// getTerminalSize returns the terminal width and height.
// Uses a pure-Go approach that works across all platforms.
func getTerminalSize(fd uintptr) (int, int, error) {
	if w, h, err := getTermSizeFromFd(int(fd)); err == nil {
		return w, h, nil
	}
	// Default fallback for unsupported platforms
	return 80, 24, nil
}
