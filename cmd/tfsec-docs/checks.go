package main

import (
	"fmt"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
	"os"
	"text/template"
)

const tmpl = `
# Checks

The checks listed below have been implemented, for more information about each check, see the wiki link provided.

| Code | Provider | Description | Wiki link |
|------|----------|-------------|-----------|
{{range $check := .}}|{{$check.Code}}|{{$check.Provider}}|{{$check.Description}}|[{{$check.Code}} Wiki](https://github.com/tfsec/tfsec/wiki/{{$check.Code}})|
{{end}}
`

func generateChecksFile(registeredChecks []scanner.Check) {
	t := template.Must(template.New("checks").Parse(tmpl))

	projectRoot, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	checksFile, err := os.Create(fmt.Sprintf("%s/CHECKS.md", projectRoot))
	if err != nil {
		panic(err)
	}

	defer checksFile.Close()
	err = t.Execute(checksFile, registeredChecks)
	if err != nil {
		panic(err)
	}
}