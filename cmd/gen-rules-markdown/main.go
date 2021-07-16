package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	_ "github.com/aquasecurity/tfsec/internal/app/tfsec/rules"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

var rootCmd = &cobra.Command{
	Use: "gen-rules-markdown",
	RunE: func(cmd *cobra.Command, args []string) error {

		projectRoot, err := os.Getwd()
		if err != nil {
			panic(err)
		}

		rulesRoot := filepath.Join(projectRoot, "internal", "app", "tfsec", "rules")
		testRoot := filepath.Join(projectRoot, "internal", "app", "tfsec", "test")

		var imports []string

		for _, rule := range scanner.GetRegisteredRules() {

			oldPath := filepath.Join(rulesRoot, fmt.Sprintf("%s.go", strings.ToLower(rule.LegacyID)))
			packageName := strings.ReplaceAll(rule.Service, "-", "")

			newBaseDir := filepath.Join(rulesRoot, string(rule.Provider), packageName)
			newBasePath := filepath.Join(newBaseDir, fmt.Sprintf("%s_rule", strings.ReplaceAll(rule.ShortCode, "-", "_")))

			newTestPath := newBasePath + "_test.go"
			newPath := newBasePath + ".go"

			oldTestPath := filepath.Join(testRoot, fmt.Sprintf("%s_test.go", strings.ToLower(rule.LegacyID)))

			importPath := fmt.Sprintf("github.com/aquasecurity/tfsec/internal/app/tfsec/rules/%s/%s", rule.Provider, packageName)
			newImp := `_ "` + importPath + `"`
			var importExists bool
			for _, imp := range imports {
				if imp == newImp {
					importExists = true
					break
				}
			}
			if !importExists {
				imports = append(imports, newImp)
			}

			if _, err := os.Stat(oldPath); err == os.ErrNotExist {
				panic(fmt.Errorf("rule definition file not found: %s", rule.LegacyID))
			}

			if err := os.MkdirAll(newBaseDir, 0700); err != nil {
				panic(err)
			}

			ruleData, err := ioutil.ReadFile(oldPath)
			if err != nil {
				panic(err)
			}

			//transform rule here
			ruleData = []byte(strings.ReplaceAll(string(ruleData), "package rules", fmt.Sprintf("package %s", packageName)))

			lines := strings.Split(string(ruleData), "\n")
			var idName string
			lines, idName = rewriteRule(rule, lines)

			fmt.Printf("Writing rule file %s from %s...", newPath, oldPath)
			if err := ioutil.WriteFile(newPath, []byte(strings.Join(lines, "\n")), 0600); err != nil {
				panic(err)
			}

			if _, err := os.Stat(oldTestPath); err == nil {
				testData, err := ioutil.ReadFile(oldTestPath)
				if err != nil {
					panic(err)
				}

				testData = []byte(strings.ReplaceAll(string(testData), `"github.com/aquasecurity/tfsec/internal/app/tfsec/rules"`, ""))
				testData = []byte(strings.ReplaceAll(string(testData), "package test", fmt.Sprintf("package %s", packageName)))
				testData = []byte(strings.ReplaceAll(string(testData), "rules."+idName, fmt.Sprintf(`"%s"`, rule.ID())))

				lines := strings.Split(string(testData), "\n")
				lines = rewriteTest(rule, idName, lines)

				fmt.Printf("Writing test file %s from %s...\n", newTestPath, oldTestPath)
				if err := ioutil.WriteFile(newTestPath, []byte(strings.Join(lines, "\n")), 0600); err != nil {
					panic(err)
				}

			}

		}

		importTemplate := fmt.Sprintf(`package rules
		
	import (
		%s
	)

		`, strings.Join(imports, "\n"))

		return ioutil.WriteFile(projectRoot+"/internal/app/tfsec/rules/init.go", []byte(importTemplate), 0600)
	},
}

func rewriteRule(rule rule.Rule, oldLines []string) ([]string, string) {
	var newLines []string

	consts := make(map[string]string)

	var inMultiLine bool
	var multi string
	var multiName string
	var idName string

	for _, line := range oldLines {

		if inMultiLine {

			multi = multi + "\n" + line
			if strings.Count(line, "`") == 1 {
				consts[multiName] = multi
				multi = ""
				inMultiLine = false
			}

			continue
		}

		if strings.Contains(line, "const ") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) < 2 {
				continue
			}
			if strings.Count(parts[1], "`") == 1 {
				inMultiLine = true
				multi = parts[1]
				multiName = strings.TrimSpace(strings.ReplaceAll(parts[0], "const", ""))
				continue
			}
			name := strings.TrimSpace(strings.ReplaceAll(parts[0], "const", ""))
			consts[name] = parts[1]
			if idName == "" {
				idName = name
			}
			continue
		}

		newLines = append(newLines, line)
	}

	var finalLines []string

	for _, line := range newLines {
		for name, val := range consts {
			line = strings.ReplaceAll(line, name+",", val+",")
		}
		finalLines = append(finalLines, line)

	}

	return finalLines, idName

}

func rewriteTest(rule rule.Rule, idName string, oldLines []string) []string {
	var newLines []string

	for _, line := range oldLines {
		// tranbsform line here...
		line = strings.ReplaceAll(line, "[placeholder]", rule.ID())
		newLines = append(newLines, line)
	}

	return newLines

}
