package terminal

import "golang.org/x/crypto/ssh/terminal"

// Size returns the width and height of the terminal, in columns and rows
func Size() (int, int) {
	width, height, _ := terminal.GetSize(0)
	return width, height
}
