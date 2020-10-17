package test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

func TestExampleCode(t *testing.T) {
	for _, check := range scanner.GetRegisteredChecks() {

		t.Run(fmt.Sprintf("Check 'good' example code for %s", check.Code), func(t *testing.T) {
			if strings.TrimSpace(check.Documentation.GoodExample) == "" {
				t.Skip("good example code not provided")
				return
			}
			results := scanSource(check.Documentation.GoodExample)
			assertCheckCode(t, "", check.Code, results)
		})

		t.Run(fmt.Sprintf("Check 'bad' example code for %s", check.Code), func(t *testing.T) {
			if strings.TrimSpace(check.Documentation.BadExample) == "" {
				t.Skip("bad example code not provided")
				return
			}
			results := scanSource(check.Documentation.BadExample)
			assertCheckCode(t, check.Code, "", results)
		})

	}
}
