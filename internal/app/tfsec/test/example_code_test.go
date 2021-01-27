package test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

func TestExampleCode(t *testing.T) {
	for _, check := range scanner.GetRegisteredChecks() {

		t.Run(fmt.Sprintf("Check explanation for %s", check.Code), func(t *testing.T) {
			if strings.TrimSpace(check.Documentation.Explanation) == "" {
				t.Fatalf("No explanation found for %s", check.Code)
			}
		})

		t.Run(fmt.Sprintf("Check 'good' example code for %s", check.Code), func(t *testing.T) {
			if strings.TrimSpace(check.Documentation.GoodExample) == "" {
				t.Fatalf("good example code not provided for %s", check.Code)
			}
			defer func() {
				if err := recover(); err != nil {
					t.Fatalf("Scan failed: %s", err)
				}
			}()
			results := scanSource(check.Documentation.GoodExample)
			assertCheckCode(t, "", check.Code, results)
		})

		t.Run(fmt.Sprintf("Check 'bad' example code for %s", check.Code), func(t *testing.T) {
			if strings.TrimSpace(check.Documentation.BadExample) == "" {
				t.Fatalf("bad example code not provided for %s", check.Code)
			}
			defer func() {
				if err := recover(); err != nil {
					t.Fatalf("Scan failed: %s", err)
				}
			}()
			results := scanSource(check.Documentation.BadExample)
			assertCheckCode(t, check.Code, "", results)
		})

	}
}
