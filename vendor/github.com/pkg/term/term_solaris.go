package term

// #include<stropts.h>
import "C"

import (
	"syscall"
	"github.com/pkg/term/termios"
	"os"
	"golang.org/x/sys/unix"
	"unsafe"
)

type attr syscall.Termios

func (a *attr) setSpeed(baud int) error {
	var rate uint32
	switch baud {
	case 50:
		rate = syscall.B50
	case 75:
		rate = syscall.B75
	case 110:
		rate = syscall.B110
	case 134:
		rate = syscall.B134
	case 150:
		rate = syscall.B150
	case 200:
		rate = syscall.B200
	case 300:
		rate = syscall.B300
	case 600:
		rate = syscall.B600
	case 1200:
		rate = syscall.B1200
	case 1800:
		rate = syscall.B1800
	case 2400:
		rate = syscall.B2400
	case 4800:
		rate = syscall.B4800
	case 9600:
		rate = syscall.B9600
	case 19200:
		rate = syscall.B19200
	case 38400:
		rate = syscall.B38400
	case 57600:
		rate = syscall.B57600
	case 115200:
		rate = syscall.B115200
	case 230400:
		rate = syscall.B230400
	case 460800:
		rate = syscall.B460800
	case 921600:
		rate = syscall.B921600
	default:
		return syscall.EINVAL
	}

	err := termios.Cfsetispeed((*syscall.Termios)(a), uintptr(rate))
	if err != nil {
		return err
	}

	err = termios.Cfsetospeed((*syscall.Termios)(a), uintptr(rate))
	if err != nil {
		return err
	}

	return nil
}

// Open opens an asynchronous communications port.
func Open(name string, options ...func(*Term) error) (*Term, error) {
	fd, e := syscall.Open(name, syscall.O_NOCTTY|syscall.O_CLOEXEC|syscall.O_NDELAY|syscall.O_RDWR, 0666)
	if e != nil {
		return nil, &os.PathError{"open", name, e}
	}

	modules := [2]string{"ptem", "ldterm"}
	for _, mod := range modules {
		err := unix.IoctlSetInt(fd, C.I_PUSH, int(uintptr(unsafe.Pointer(syscall.StringBytePtr(mod)))))
		if err != nil {
			return nil, err
		}
	}

	t := Term{name: name, fd: fd}
	termios.Tcgetattr(uintptr(t.fd), &t.orig)
	if err := termios.Tcgetattr(uintptr(t.fd), &t.orig); err != nil {
		return nil, err
	}

	if err := t.SetOption(options...); err != nil {
		return nil, err
	}

	return &t, syscall.SetNonblock(t.fd, false)
}

// Restore restores the state of the terminal captured at the point that
// the terminal was originally opened.
func (t *Term) Restore() error {
	return termios.Tcsetattr(uintptr(t.fd), termios.TCSANOW, &t.orig)
}
