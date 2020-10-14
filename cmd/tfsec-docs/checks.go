package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/template"
)

const checksTableTemplate = `---
permalink: /docs/{{$.Provider}}/home/
---

The included {{$.Provider | ToUpper}} checks are listed below. For more information about each check, see the link provided.

| Code  | Summary | Details |
|:-------|:-------------|:----------|
{{range $check := .Checks}}|{{$check.Code}}|{{$check.Documentation.Summary}}|[{{$check.Code}}](/docs/{{$.Provider}}/{{$check.Code}})|
{{end}}
`

func generateChecksFiles(registeredChecks []*FileContent) error {
	for _, checkFileContent := range registeredChecks {
		if err := generateCheckFile(checkFileContent); err != nil {
			return err
		}
	}
	return nil
}

func generateCheckFile(checkFileContent *FileContent) error {
	checkTmpl, err := template.New("checks").Funcs(funcMap).Parse(checksTableTemplate)
	if err != nil {
		return err
	}

	providerFilePath := fmt.Sprintf("%s/_docs/%s/home.md", webPath, strings.ToLower(checkFileContent.Provider))
	if err := os.MkdirAll(filepath.Dir(providerFilePath), os.ModePerm); err != nil {
		return err
	}
	return writeTemplate(checkFileContent, providerFilePath, checkTmpl)

}
