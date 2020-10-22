package prompt

import (
	"bufio"
	"fmt"
	"os"

	"github.com/liamg/clinch/terminal"
)

// EnterInput requests input from the user with the given message, and returns any user input that was gathered until a newline was entered
func EnterInput(msg string) string {
	terminal.ClearLine()
	terminal.PrintImportantf(msg)
	reader := bufio.NewReader(os.Stdin)
	input, err := reader.ReadString('\n')
	if err != nil || len(input) <= 1 {
		return ""
	}
	s := input[:len(input)-1]
	if s[len(s)-1] == '\r' {
		s = input[:len(input)-1]
	}
	return s
}

// EnterInputWithDefault requests input from the user with the given message and returns a default if the input is empty
func EnterInputWithDefault(msg, defaultValue string) string {
	input := EnterInput(fmt.Sprintf("%v [%v]: ", msg, defaultValue))
	if len(input) == 0 {
		input = defaultValue
	}
	return input
}
