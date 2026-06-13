//go:build linux || darwin

package display

import (
	"fmt"
	"syscall"
	"unsafe"
)

type winsize struct {
	Row    uint16
	Col    uint16
	Xpixel uint16
	Ypixel uint16
}

func getTermSizeFromFd(fd int) (int, int, error) {
	var ws winsize
	_, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL,
		uintptr(fd),
		syscall.TIOCGWINSZ,
		uintptr(unsafe.Pointer(&ws)),
	)
	if errno != 0 {
		return 0, 0, fmt.Errorf("ioctl TIOCGWINSZ failed: %v", errno)
	}
	return int(ws.Col), int(ws.Row), nil
}
