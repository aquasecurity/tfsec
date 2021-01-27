package prompt

import (
	"fmt"
	"github.com/liamg/clinch/terminal"
	"github.com/liamg/tml"
	"github.com/pkg/term"
)

const (
	SPACE  = 32
	UP     = 65
	DOWN   = 66
	ESCAPE = 27
	RETURN = 13

	ROW_OFFSET     = 2
	DEFAULT_COLUMN = 0
)

type listItem struct {
	index    int
	value    string
	selected bool
	colour   string
}

var ErrNoOptionsProvided = fmt.Errorf("no options were provided")

func (item *listItem) toString() string {
	check := " "
	if item.selected {
		check = "X"
	}
	return fmt.Sprintf(" <darkgrey>[</darkgrey>%v<darkgrey>]</darkgrey> <%s>%v\n", check, item.colour, item.value)
}

func ChooseFromMultiList(message string, options []string) ([]int, []string, error) {
	if len(options) == 0 {
		return nil, nil, ErrNoOptionsProvided
	}
	var items []*listItem
	colours := []string{"lightblue", "lightgreen", "lightyellow", "white"}
	for index, option := range options {
		col := colours[index%len(colours)]
		items = append(items, &listItem{index: index, value: option, colour: col})
	}
	return getListSelection(message, items)
}

func getListSelection(message string, items []*listItem) ([]int, []string, error) {
	fmt.Printf("\n %s\n\n", message)
	currentPos := 0
	drawItems(items, currentPos, false)

keyInput:
	for {
		keyCode, err := getKeyInput()
		if err != nil {
			return nil, nil, err
		}
		switch keyCode {
		case DOWN:
			if currentPos < len(items)-1 {
				terminal.MoveCursorDown(1)
				currentPos += 1
			}
		case UP:
			if currentPos > 0 {
				terminal.MoveCursorUp(1)
				currentPos -= 1
			}
		case SPACE:
			items[currentPos].selected = !items[currentPos].selected
			drawItems(items, currentPos, true)
		case ESCAPE:
			resetPrompt(len(items) - currentPos)
			return []int{}, []string{}, ErrUserCancelled
		case RETURN:
			break keyInput
		}
	}
	resetPrompt(len(items) - currentPos)

	var selectedIndexes []int
	var selectedValues []string

	for _, item := range items {
		if !item.selected {
			continue
		}
		selectedIndexes = append(selectedIndexes, item.index)
		selectedValues = append(selectedValues, item.value)
	}
	return selectedIndexes, selectedValues, nil
}

func resetPrompt(rowPosition int) {
	terminal.MoveCursorDown(rowPosition + ROW_OFFSET - 1)
	terminal.ClearLine()
	terminal.MoveCursorToColumn(DEFAULT_COLUMN)
}

func drawItems(items []*listItem, currentPos int, isRedraw bool) {
	if isRedraw {
		terminal.MoveCursorUp(currentPos)
		terminal.MoveCursorToColumn(-2)
	}

	for _, item := range items {
		_ = tml.Printf(item.toString())
	}
	fmt.Println("")
	fmt.Println(" space to toggle, return to accept. (Esc to cancel): ")
	terminal.MoveCursorUp(len(items) - currentPos + ROW_OFFSET)
	terminal.MoveCursorToColumn(1)
}

func getKeyInput() (keyCode int, err error) {
	t, err := term.Open("/dev/tty")
	if err != nil {
		return 0, err
	}
	err = term.RawMode(t)
	if err != nil {
		return 0, err
	}
	bytes := make([]byte, 3)

	var numRead int
	numRead, err = t.Read(bytes)
	if err != nil {
		return 0, err
	}
	if numRead == 3 && bytes[0] == 27 && bytes[1] == 91 {
		switch bytes[2] {
		case UP, DOWN:
			keyCode = int(bytes[2])
		}
	} else if numRead == 1 {
		switch bytes[0] {
		case ESCAPE, RETURN, SPACE:
			keyCode = int(bytes[0])
		}
	}
	t.Restore()
	t.Close()
	return
}
