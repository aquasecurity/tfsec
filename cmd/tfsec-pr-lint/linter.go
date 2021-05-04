package main

import (
	"fmt"

	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

type linter struct {
	count    int
	exitCode int
}

func (l *linter) lint(check scanner.Check) {
	docs := check.Documentation
	var errorFound = false
	if err := l.checkDocPart(string(docs.Summary), "Summary"); err != nil {
		fmt.Printf("%s: %s\n", check.Code, err.Error())
		errorFound = true
	}
	if err := l.checkDocPart(docs.Impact, "Impact"); err != nil {
		fmt.Printf("%s: %s\n", check.Code, err.Error())
		errorFound = true
	}
	if err := l.checkDocPart(docs.Resolution, "Resolution"); err != nil {
		fmt.Printf("%s: %s\n", check.Code, err.Error())
		errorFound = true
	}
	if err := l.checkDocPart(docs.Explanation, "Explanation"); err != nil {
		fmt.Printf("%s: %s\n", check.Code, err.Error())
		errorFound = true
	}
	if err := l.checkDocPart(docs.GoodExample, "GoodExample"); err != nil {
		fmt.Printf("%s: %s\n", check.Code, err.Error())
		errorFound = true
	}
	if err := l.checkDocPart(docs.BadExample, "BadExample"); err != nil {
		fmt.Printf("%s: %s\n", check.Code, err.Error())
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
