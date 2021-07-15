package main

import (
	"fmt"
	"math"
	"os"

	"github.com/aquasecurity/tfsec/pkg/rule"
)

type linter struct {
	count int
}

func (l *linter) lint(check rule.Rule) {
	// crashout immediately if there is a check with no id
	if check.LegacyID == "" {
		fmt.Printf("Found a check with no ID\n")
		os.Exit(1)
	}
	errorFound := l.checkDocumentation(check)
	if len(check.RequiredTypes) == 0 {
		fmt.Printf("%s: missing required types\n", check.LegacyID)
		errorFound = true
	}

	if errorFound {
		l.count += 1
	}
}

func (l *linter) checkDocumentation(check rule.Rule) bool {
	docs := check.Documentation
	var errorFound bool
	if err := l.verifyPart(string(docs.Summary), "Summary"); err != nil {
		fmt.Printf("%s: %s\n", check.LegacyID, err.Error())
		errorFound = true
	}
	if err := l.verifyPart(docs.Impact, "Impact"); err != nil {
		fmt.Printf("%s: %s\n", check.LegacyID, err.Error())
		errorFound = true
	}
	if err := l.verifyPart(docs.Resolution, "Resolution"); err != nil {
		fmt.Printf("%s: %s\n", check.LegacyID, err.Error())
		errorFound = true
	}
	if err := l.verifyPart(docs.Explanation, "Explanation"); err != nil {
		fmt.Printf("%s: %s\n", check.LegacyID, err.Error())
		errorFound = true
	}
	if err := l.verifyPart(docs.GoodExample, "GoodExample"); err != nil {
		fmt.Printf("%s: %s\n", check.LegacyID, err.Error())
		errorFound = true
	}
	if err := l.verifyPart(docs.BadExample, "BadExample"); err != nil {
		fmt.Printf("%s: %s\n", check.LegacyID, err.Error())
		errorFound = true
	}

	if len(docs.Links) == 0 {
		fmt.Printf("%s: Has no links configure\n", check.LegacyID)
		errorFound = true
	}
	return errorFound
}

func (l *linter) verifyPart(checkPart, checkDescription string) error {
	if checkPart == "" {
		return fmt.Errorf("[%s] documentation is empty", checkDescription)
	}

	return nil
}

func (l *linter) exitCode() int {
	return int(math.Min(1, float64(l.count)))
}
