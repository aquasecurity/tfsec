// +build !windows

package term

import (
	"syscall"
	"time"

	"github.com/pkg/term/termios"
)

// Term represents an asynchronous communications port.
type Term struct {
	name string
	fd   int
	orig syscall.Termios // original state of the terminal, see Open and Restore
}

// SetCbreak sets cbreak mode.
func (t *Term) SetCbreak() error {
	return t.SetOption(CBreakMode)
}

// CBreakMode places the terminal into cbreak mode.
func CBreakMode(t *Term) error {
	var a attr
	if err := termios.Tcgetattr(uintptr(t.fd), (*syscall.Termios)(&a)); err != nil {
		return err
	}
	termios.Cfmakecbreak((*syscall.Termios)(&a))
	return termios.Tcsetattr(uintptr(t.fd), termios.TCSANOW, (*syscall.Termios)(&a))
}

// SetRaw sets raw mode.
func (t *Term) SetRaw() error {
	return t.SetOption(RawMode)
}

// RawMode places the terminal into raw mode.
func RawMode(t *Term) error {
	var a attr
	if err := termios.Tcgetattr(uintptr(t.fd), (*syscall.Termios)(&a)); err != nil {
		return err
	}
	termios.Cfmakeraw((*syscall.Termios)(&a))
	return termios.Tcsetattr(uintptr(t.fd), termios.TCSANOW, (*syscall.Termios)(&a))
}

// Speed sets the baud rate option for the terminal.
func Speed(baud int) func(*Term) error {
	return func(t *Term) error {
		return t.setSpeed(baud)
	}
}

// SetSpeed sets the receive and transmit baud rates.
func (t *Term) SetSpeed(baud int) error {
	return t.SetOption(Speed(baud))
}

func (t *Term) setSpeed(baud int) error {
	var a attr
	if err := termios.Tcgetattr(uintptr(t.fd), (*syscall.Termios)(&a)); err != nil {
		return err
	}
	a.setSpeed(baud)
	return termios.Tcsetattr(uintptr(t.fd), termios.TCSANOW, (*syscall.Termios)(&a))
}

func clamp(v, lo, hi int64) int64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// timeoutVals converts d into values suitable for termios VMIN and VTIME ctrl chars
func timeoutVals(d time.Duration) (uint8, uint8) {
	if d > 0 {
		// VTIME is expressed in terms of deciseconds
		vtimeDeci := d.Nanoseconds() / 1e6 / 100
		// ensure valid range
		vtime := uint8(clamp(vtimeDeci, 1, 0xff))
		return 0, vtime
	}
	// block indefinitely until we receive at least 1 byte
	return 1, 0
}

// ReadTimeout sets the read timeout option for the terminal.
func ReadTimeout(d time.Duration) func(*Term) error {
	return func(t *Term) error {
		return t.setReadTimeout(d)
	}
}

// SetReadTimeout sets the read timeout.
// A zero value for d means read operations will not time out.
func (t *Term) SetReadTimeout(d time.Duration) error {
	return t.SetOption(ReadTimeout(d))
}

func (t *Term) setReadTimeout(d time.Duration) error {
	var a attr
	if err := termios.Tcgetattr(uintptr(t.fd), (*syscall.Termios)(&a)); err != nil {
		return err
	}
	a.Cc[syscall.VMIN], a.Cc[syscall.VTIME] = timeoutVals(d)
	return termios.Tcsetattr(uintptr(t.fd), termios.TCSANOW, (*syscall.Termios)(&a))
}

// FlowControl sets the flow control option for the terminal.
func FlowControl(kind int) func(*Term) error {
	return func(t *Term) error {
		return t.setFlowControl(kind)
	}
}

// SetFlowControl sets whether hardware flow control is enabled.
func (t *Term) SetFlowControl(kind int) error {
	return t.SetOption(FlowControl(kind))
}

func (t *Term) setFlowControl(kind int) error {
	var a attr
	if err := termios.Tcgetattr(uintptr(t.fd), (*syscall.Termios)(&a)); err != nil {
		return err
	}
	switch kind {
	case NONE:
		a.Iflag &^= termios.IXON | termios.IXOFF | termios.IXANY
		a.Cflag &^= termios.CRTSCTS

	case XONXOFF:
		a.Cflag &^= termios.CRTSCTS
		a.Iflag |= termios.IXON | termios.IXOFF | termios.IXANY

	case HARDWARE:
		a.Iflag &^= termios.IXON | termios.IXOFF | termios.IXANY
		a.Cflag |= termios.CRTSCTS
	}
	return termios.Tcsetattr(uintptr(t.fd), termios.TCSANOW, (*syscall.Termios)(&a))
}

// Flush flushes both data received but not read, and data written but not transmitted.
func (t *Term) Flush() error {
	return termios.Tcflush(uintptr(t.fd), termios.TCIOFLUSH)
}

// SendBreak sends a break signal.
func (t *Term) SendBreak() error {
	return termios.Tcsendbreak(uintptr(t.fd), 0)
}

// SetDTR sets the DTR (data terminal ready) signal.
func (t *Term) SetDTR(v bool) error {
	bits := syscall.TIOCM_DTR
	if v {
		return termios.Tiocmbis(uintptr(t.fd), &bits)
	} else {
		return termios.Tiocmbic(uintptr(t.fd), &bits)
	}
}

// DTR returns the state of the DTR (data terminal ready) signal.
func (t *Term) DTR() (bool, error) {
	var status int
	err := termios.Tiocmget(uintptr(t.fd), &status)
	return status&syscall.TIOCM_DTR == syscall.TIOCM_DTR, err
}

// SetRTS sets the RTS (data terminal ready) signal.
func (t *Term) SetRTS(v bool) error {
	bits := syscall.TIOCM_RTS
	if v {
		return termios.Tiocmbis(uintptr(t.fd), &bits)
	} else {
		return termios.Tiocmbic(uintptr(t.fd), &bits)
	}
}

// RTS returns the state of the RTS (data terminal ready) signal.
func (t *Term) RTS() (bool, error) {
	var status int
	err := termios.Tiocmget(uintptr(t.fd), &status)
	return status&syscall.TIOCM_RTS == syscall.TIOCM_RTS, err
}

// Close closes the device and releases any associated resources.
func (t *Term) Close() error {
	err := syscall.Close(t.fd)
	t.fd = -1
	return err
}
