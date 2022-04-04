package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/aquasecurity/defsec/pkg/providers"
)

type templateObject struct {
	ID          string
	ShortCode   string
	LegacyID    string
	Severity    string
	Summary     string
	Service     string
	Provider    string
	Explanation string
	Impact      string
	Resolution  string
	BadExample  string
	GoodExample string
	Links       []string
}

func generateWebPages(fileContents []*FileContent) error {
	for _, contents := range fileContents {
		for _, check := range contents.Checks {
			webProviderPath := filepath.Join(webPath, strings.ToLower(check.Provider), strings.ToLower(check.Service))
			if err := generateWebPage(webProviderPath, check); err != nil {
				return err
			}
		}
	}
	return nil
}

var funcMap = template.FuncMap{
	"ToUpper":            strings.ToUpper,
	"ToLower":            strings.ToLower,
	"FormatProviderName": formatProviderName,
	"Join":               join,
}

func join(s []string) string {
	if s == nil {
		return ""
	}
	return strings.Join(s[1:], s[0])
}

func formatProviderName(providerName string) string {
	if providerName == "digitalocean" {
		providerName = "digital ocean"
	}
	return providers.Provider(providerName).DisplayName()
}

func generateWebPage(webProviderPath string, r templateObject) error {

	if err := os.MkdirAll(webProviderPath, os.ModePerm); err != nil {
		return err
	}
	filePath := filepath.Join(webProviderPath, r.ShortCode, "index.md")
	if err := os.MkdirAll(filepath.Dir(filePath), 0755); err != nil {
		return err
	}
	fmt.Printf("Generating page for %s at %s\n", r.ID, filePath)
	webTmpl := template.Must(template.New("web").Funcs(funcMap).Parse(baseWebPageTemplate))

	return writeTemplate(r, filePath, webTmpl)

}

func writeTemplate(contents interface{}, path string, tmpl *template.Template) error {
	outputFile, err := os.Create(path)
	if err != nil {
		return err
	}
	defer func() { _ = outputFile.Close() }()
	return tmpl.Execute(outputFile, contents)
}

const baseWebPageTemplate = `---
title: {{$.Summary}}
---

# {{$.Summary}}

### Default Severity: <span class="severity {{$.Severity | ToLower }}">{{$.Severity }}</span>

### Explanation

{{$.Explanation}}

### Possible Impact
{{$.Impact}}

### Suggested Resolution
{{$.Resolution}}

{{if $.BadExample }}
### Insecure Example

The following example will fail the {{$.ID}} check.
` + "```terraform" + `
{{ $.BadExample }}
` + "```" + `

{{end}}
{{if $.GoodExample }}
### Secure Example

The following example will pass the {{$.ID}} check.
` + "```terraform" + `
{{ $.GoodExample }}
` + "```" + `
{{end}}

{{if $.Links}}
### Links

{{range $link := $.Links}}
- [{{.}}]({{.}}){:target="_blank" rel="nofollow noreferrer noopener"}
{{end}}
{{end}}

`
