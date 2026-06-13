//go:build !linux && !darwin

package display

import "fmt"

func getTermSizeFromFd(fd int) (int, int, error) {
	return 0, 0, fmt.Errorf("terminal size detection not supported on this platform")
}
