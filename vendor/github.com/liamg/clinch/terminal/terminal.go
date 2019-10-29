package terminal

import "fmt"

// Reset terminal to it's initial state, destroying scroll buffer
func Reset() {
	fmt.Println("\x1b[3J")
}

// Clear current terminal screen (keeps scroll buffer intact)
func Clear() {
	fmt.Printf("\x1b[2J")
}

// SetAltBuffer switches to the alternate screen buffer
func SetAltBuffer() {
	fmt.Printf("\x1b[?1049h")
}

// SetMainBuffer switches to the main screen buffer
func SetMainBuffer() {
	fmt.Printf("\x1b[?1049l")
}

// SaveCursor saves the position of the cursor
func SaveCursor() {
	fmt.Printf("\033[s")
}

// RestoreCursor restores the position of the cursor to the last position saved with SaveCursor
func RestoreCursor() {
	fmt.Printf("\033[u")
}

// ShowCursor makes the cursor position highlighted
func ShowCursor() {
	fmt.Printf("\033[?25h")
}

// HideCursor hides the cursor
func HideCursor() {
	fmt.Printf("\033[?25l")
}

// MoveCursorToColumn moves the cursor to the given column (zero indexed)
func MoveCursorToColumn(column int) {
	fmt.Printf("\r\033[%dC", column+1)
}

// MoveCursorTo moves the cursor to the given position (zero indexed)
func MoveCursorTo(column int, row int) {
	fmt.Printf("\033[%d;%dH", row+1, column+1)
}

// ClearLine removes all content from the current line and moves the cursor to the beginning of the line
func ClearLine() {
	fmt.Printf("\033[2K\r")
}
