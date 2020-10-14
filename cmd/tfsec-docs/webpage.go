package main

import (
	"fmt"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
	"os"
	"strings"
	"text/template"
)

const (
	docsDataFile = `
- title: Getting Started
  docs:
  - home


{{range $p := .}}
- title: {{$p.Provider | ToUpper }} Checks
  docs:
  - {{$p.Provider}}/home
{{range $check := $p.Checks}}  - {{$check.Provider}}/{{$check.Code}}
{{end}}{{end}}`

	baseWebPageTemplate = `---
title: {{$.Code}}
permalink: /docs/{{$.Provider}}/{{$.Code}}/
---

{{$.Description}}

## Explanation

## Example

` + "```" + `
"resource" "example" {
	todo
}
` + "```" + `

## Terraform Documentation
`
)

func generateWebPages(fileContents []*FileContent) {
	for _, contents := range fileContents {
		for _, check := range contents.Checks {
			generateWebPage(check)
		}
	}
	generateDocsDataFile(fileContents)
}

func generateDocsDataFile(contents []*FileContent) {
	docsFilePath := fmt.Sprintf("%s/_data/docs.yml", webPath)
	docTmpl := template.Must(template.New("web").Funcs(funcMap).Parse(docsDataFile))
	writeTemplate(contents, docsFilePath, docTmpl)
}

func generateWebPage(check scanner.Check) {
	webProviderPath := fmt.Sprintf("%s/_docs/%s", webPath, strings.ToLower(string(check.Provider)))
	if !fileExists(webProviderPath) {
		if err := os.MkdirAll(webProviderPath, os.ModePerm); err != nil {
			panic(err)
		}
	}

	filePath := fmt.Sprintf("%s/%s.md", webProviderPath, check.Code)
	if fileExists(filePath) {
		fmt.Printf("Not generating web page for %s, it already exists\n", check.Code)
	}
	fmt.Printf("Generating wiki page for %s at %s\n", check.Code, filePath)
	webTmpl := template.Must(template.New("web").Parse(baseWebPageTemplate))
	writeTemplate(check, filePath, webTmpl)
}
