package term

import "syscall"

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
	case 500000:
		rate = syscall.B500000
	case 576000:
		rate = syscall.B576000
	case 921600:
		rate = syscall.B921600
	case 1000000:
		rate = syscall.B1000000
	case 1152000:
		rate = syscall.B1152000
	case 1500000:
		rate = syscall.B1500000
	case 2000000:
		rate = syscall.B2000000
	case 2500000:
		rate = syscall.B2500000
	case 3000000:
		rate = syscall.B3000000
	case 3500000:
		rate = syscall.B3500000
	case 4000000:
		rate = syscall.B4000000
	default:
		return syscall.EINVAL
	}
	(*syscall.Termios)(a).Cflag = syscall.CS8 | syscall.CREAD | syscall.CLOCAL | rate
	(*syscall.Termios)(a).Ispeed = rate
	(*syscall.Termios)(a).Ospeed = rate
	return nil
}
