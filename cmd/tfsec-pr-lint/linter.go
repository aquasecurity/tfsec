package main

import (
	"fmt"
	"math"
	"os"
	"strings"

	"github.com/aquasecurity/tfsec/pkg/rule"
)

type linter struct {
	count int
}

func (l *linter) lint(check rule.Rule) {
	// crashout immediately if there is a check with no id
	if check.ShortCode == "" {
		fmt.Printf("%s: Found a check with no short code\n", check.ID())
		os.Exit(1)
	}
	if check.Service == "" {
		fmt.Printf("%s: Found a check with no service\n", check.ID())
		os.Exit(1)
	}
	if check.Provider == "" {
		fmt.Printf("%s: Found a check with no provider\n", check.ID())
		os.Exit(1)
	}
	if len(check.Documentation.Links) == 0 {
		fmt.Printf("%s: Found check with no links\n", check.ID())
		os.Exit(1)
	}

	errorFound := l.checkDocumentation(check)
	if len(check.RequiredTypes) == 0 {
		fmt.Printf("%s: missing required types\n", check.ID())
		errorFound = true
	}

	if errorFound {
		l.count += 1
	}
}

func (l *linter) checkDocumentation(check rule.Rule) bool {
	docs := check.Documentation

	var errorFound bool
	if !strings.Contains(check.Documentation.Links[0], ".terraform.io") {
		fmt.Printf("%s: The first link should be Terraform for consistency\n", check.ID())
		errorFound = true
	}

	if err := l.verifyPart(string(docs.Summary), "Summary"); err != nil {
		fmt.Printf("%s: %s\n", check.ID(), err.Error())
		errorFound = true
	}
	if err := l.verifyPart(docs.Impact, "Impact"); err != nil {
		fmt.Printf("%s: %s\n", check.ID(), err.Error())
		errorFound = true
	}
	if err := l.verifyPart(docs.Resolution, "Resolution"); err != nil {
		fmt.Printf("%s: %s\n", check.ID(), err.Error())
		errorFound = true
	}
	if err := l.verifyPart(docs.Explanation, "Explanation"); err != nil {
		fmt.Printf("%s: %s\n", check.ID(), err.Error())
		errorFound = true
	}
	for _, goodExample := range docs.GoodExample {
		if err := l.verifyPart(goodExample, "GoodExample"); err != nil {
			fmt.Printf("%s: %s\n", check.ID(), err.Error())
			errorFound = true
		}
	}
	for _, badExample := range docs.BadExample {
		if err := l.verifyPart(badExample, "BadExample"); err != nil {
			fmt.Printf("%s: %s\n", check.ID(), err.Error())
			errorFound = true
		}
	}

	if len(docs.Links) == 0 {
		fmt.Printf("%s: Has no links configure\n", check.ID())
		errorFound = true
	}
	return errorFound
}

func (l *linter) verifyPart(checkPart, checkDescription string) error {
	if strings.TrimSpace(checkPart) == "" {
		return fmt.Errorf("[%s] documentation is empty", checkDescription)
	}

	return nil
}

func (l *linter) exitCode() int {
	return int(math.Min(1, float64(l.count)))
}
