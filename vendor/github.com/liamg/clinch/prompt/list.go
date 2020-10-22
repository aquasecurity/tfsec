package prompt

import (
	"fmt"
	"strconv"

	"github.com/liamg/tml"
)

// ErrUserCancelled means the user cancelled the current action
var ErrUserCancelled = fmt.Errorf("User cancelled")

// ErrUserChoiceInvalid means the user chose an option which was not valid
var ErrUserChoiceInvalid = fmt.Errorf("User choice invalid")

// ChooseFromList prompts the user to select an item from a list. It return the chosen list index, the chosen list item value, or an error
func ChooseFromList(message string, options []string) (int, string, error) {
	fmt.Printf("\n %s\n\n", message)
	colours := []string{"lightblue", "lightgreen", "lightyellow", "white"}

	for i, option := range options {
		col := colours[i%len(colours)]
		pad := ""
		if i+1 < 10 { // ocd padding
			pad = " "
		}
		tml.Printf(
			fmt.Sprintf(" %%s<darkgrey>[</darkgrey><%s>%%d<darkgrey>]</darkgrey> <%s>%%s\n", col, col),
			pad,
			i+1,
			option,
		)
	}
	fmt.Println("")
	choice := EnterInput("Enter choice (blank to cancel): ")
	fmt.Println("")

	if choice == "" {
		return -1, "", ErrUserCancelled
	}

	for i, opt := range options {
		if opt == choice {
			return i, opt, nil
		}
	}

	choiceIndex, err := strconv.Atoi(choice)
	if err != nil || choiceIndex-1 >= len(options) || choiceIndex <= 0 {
		return -1, "", ErrUserChoiceInvalid
	}

	return choiceIndex - 1, options[choiceIndex-1], nil
}
