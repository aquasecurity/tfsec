package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/template"
)

const checksTableTemplate = `---
title: {{$.Provider | FormatProviderName }} Checks
permalink: /docs/{{$.Provider}}/home/
has_children: true
has_toc: false
---

The included {{$.Provider | FormatProviderName }} checks are listed below. For more information about each check, see the link provided.

| ID  | Summary |
|:-------|:-------------|
{{range $check := .Checks}}|[{{$check.ID}}](/docs/{{$.Provider}}/{{$check.ID}})|{{$check.Documentation.Summary}}|
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

	providerFilePath := fmt.Sprintf("%s/docs/%s/home.md", webPath, strings.ToLower(checkFileContent.Provider))
	if err := os.MkdirAll(filepath.Dir(providerFilePath), os.ModePerm); err != nil {
		return err
	}
	return writeTemplate(checkFileContent, providerFilePath, checkTmpl)

}
