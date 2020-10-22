package prompt

import (
	"syscall"

	"github.com/liamg/clinch/terminal"
	sshterm "golang.org/x/crypto/ssh/terminal"
)

// EnterPassword requests input from the user with the given message, hiding that input, and returns any user input that was gathered until a newline was entered
func EnterPassword(msg string) string {
	terminal.ClearLine()
	terminal.PrintImportantf(msg)
	bytePassword, err := sshterm.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return ""
	}
	return string(bytePassword)
}
