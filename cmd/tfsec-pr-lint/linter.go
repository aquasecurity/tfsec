package main

import (
	"fmt"

	"github.com/tfsec/tfsec/pkg/rule"
)

type linter struct {
	count    int
	exitCode int
}

func (l *linter) lint(check rule.Rule) {
	docs := check.Documentation
	var errorFound = false
	if err := l.checkDocPart(string(docs.Summary), "Summary"); err != nil {
		fmt.Printf("%s: %s\n", check.ID, err.Error())
		errorFound = true
	}
	if err := l.checkDocPart(docs.Impact, "Impact"); err != nil {
		fmt.Printf("%s: %s\n", check.ID, err.Error())
		errorFound = true
	}
	if err := l.checkDocPart(docs.Resolution, "Resolution"); err != nil {
		fmt.Printf("%s: %s\n", check.ID, err.Error())
		errorFound = true
	}
	if err := l.checkDocPart(docs.Explanation, "Explanation"); err != nil {
		fmt.Printf("%s: %s\n", check.ID, err.Error())
		errorFound = true
	}
	if err := l.checkDocPart(docs.GoodExample, "GoodExample"); err != nil {
		fmt.Printf("%s: %s\n", check.ID, err.Error())
		errorFound = true
	}
	if err := l.checkDocPart(docs.BadExample, "BadExample"); err != nil {
		fmt.Printf("%s: %s\n", check.ID, err.Error())
		errorFound = true
	}

	if len(docs.Links) == 0 {
		fmt.Printf("%s: Has no links configure\n", check.ID)
		errorFound = true
	}

	if errorFound {
		l.count += 1
	}
}

func (l *linter) checkDocPart(checkPart, checkDescription string) error {
	if checkPart == "" {
		l.exitCode = 1
		return fmt.Errorf("[%s] documentation is empty", checkDescription)

	}

	return nil
}
