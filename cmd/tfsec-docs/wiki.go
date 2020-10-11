package main

import (
	"fmt"
	"os"
	"strings"
	"text/template"

	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

const (
	baseWikiTemplate = `

## Check Description

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

	sidebarTemplate = `## [HOME](Home)

{{range $p := .}}
### [{{$p.Provider | ToUpper }}]({{$p.Provider | ToUpper }})
{{range $check := $p.Checks}}- [{{$check.Code}}]({{$check.Code}})
{{end}}{{end}}`
)

var funcMap = template.FuncMap{
	"ToUpper": strings.ToUpper,
}

func generateWikiPages(fileContents []*FileContent) {
	for _, contents := range fileContents {
		for _, check := range contents.Checks {
			generateWikiPage(check, wikiPath)
		}
	}
	updateSideBar(fileContents)
}

func updateSideBar(contents []*FileContent) {
	sideBarPath := fmt.Sprintf("%s/_Sidebar.md", wikiPath)

	sideBarTmpl := template.Must(template.New("sidebar").Funcs(funcMap).Parse(sidebarTemplate))

	writeTemplate(contents, sideBarPath, sideBarTmpl)
}

func generateWikiPage(check scanner.Check, wikiPath string) {
	wikiProviderPath := fmt.Sprintf("%s/%s", wikiPath, strings.ToLower(string(check.Provider)))
	if !fileExists(wikiProviderPath) {
		if err := os.MkdirAll(wikiProviderPath, os.ModePerm); err != nil {
			panic(err)
		}
	}

	filePath := fmt.Sprintf("%s/%s.md", wikiProviderPath, check.Code)
	if fileExists(filePath) {
		fmt.Printf("Not generating wiki page for %s, it already exists\n", check.Code)
	}
	fmt.Printf("Generating wiki page for %s at %s\n", check.Code, filePath)
	wikiTmpl := template.Must(template.New("wiki").Parse(baseWikiTemplate))
	writeTemplate(check, filePath, wikiTmpl)
}

func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}
