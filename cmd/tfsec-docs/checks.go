package main

import (
	"fmt"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
	"os"
	"sort"
	"strings"
	"text/template"
)

const tmpl = `
# Checks - {{$.Provider}}

The {{$.Provider}} checks listed below have been implemented, for more information about each check, see the wiki link provided.

| Code  | Description | Wiki link |
|:-------|:-------------|:----------|
{{range $check := .Checks}}|{{$check.Code}}|{{$check.Provider}}|{{$check.Description}}|[{{$check.Code}} Wiki](https://github.com/tfsec/tfsec/wiki/{{$check.Code}})|
{{end}}
`

type FileContent struct {
	Provider string
	Checks   []scanner.Check
}

func generateChecksFiles(registeredChecks []scanner.Check) {
	checkMap := splitChecksIntoProviders(registeredChecks)

	for provider, checks := range checkMap {
		sortChecks(checks)
		checkFileContent := &FileContent{Provider: provider, Checks: checks}

		generateCheckFile(checkFileContent)
	}
}

func generateCheckFile(checkFileContent *FileContent) {
	t := template.Must(template.New("checks").Parse(tmpl))

	projectRoot, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	checksFile, err := os.Create(fmt.Sprintf("%s/docs/%s_CHECKS.md", projectRoot, strings.ToUpper(checkFileContent.Provider)))
	if err != nil {
		panic(err)
	}

	defer checksFile.Close()
	err = t.Execute(checksFile, checkFileContent)
	if err != nil {
		panic(err)
	}
}

func sortChecks(checks []scanner.Check) {
	sort.Slice(checks, func(i, j int) bool {
		return checks[i].Code < checks[j].Code
	})
}

func splitChecksIntoProviders(checks []scanner.Check) map[string][]scanner.Check {
	checkMap := make(map[string][]scanner.Check)

	for _, check := range checks {
		provider := string(check.Provider)
		checkMap[provider] = append(checkMap[provider], check)
	}
	return checkMap
}
