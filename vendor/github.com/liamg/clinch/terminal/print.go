package terminal

import (
	"bufio"
	"fmt"
	"os"

	"github.com/liamg/tml"
)

// PrintErrorf prints a string to stdout in bold, red text
func PrintErrorf(message string, args ...interface{}) {
	tml.Printf("<red><bold>"+message, args...)
}

// PrintImportantf prints a string to stdout in bold, light blue text
func PrintImportantf(message string, args ...interface{}) {
	tml.Printf("<lightblue><bold>"+message, args...)
}

// PrintSuccessf prints a string to stdout in bold, green text
func PrintSuccessf(message string, args ...interface{}) {
	tml.Printf("<green><bold>"+message, args...)
}

// ShowSensitiveData will output a sensitive string in the alt buffer, and reset the terminal once the user presses enter, wiping all trace of the secret from the terminal display buffer
func ShowSensitiveData(data string) {

	SetAltBuffer()
	Clear()
	HideCursor()
	MoveCursorTo(0, 0)

	fmt.Println("The following data is sensitive and will only be displayed temporarily. It will not be visible in your terminal's scroll buffer.")
	fmt.Println("")

	fmt.Printf("%s\n", data)
	fmt.Println("")

	PrintImportantf("Press [enter] to return to your shell.")
	_, _ = bufio.NewReader(os.Stdin).ReadBytes('\n')

	Clear()
	ShowCursor()
	Reset()
	SetMainBuffer()
}
