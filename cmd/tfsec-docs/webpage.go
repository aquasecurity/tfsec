package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

const (
	docsDataFile = `
{{range $p := .}}
- title: {{$p.Provider | ToUpper }} Checks
  docs:
  - {{$p.Provider}}/home
{{range $check := $p.Checks}}  - {{$check.Provider}}/{{$check.Code}}
{{end}}{{end}}
`

	baseWebPageTemplate = `---
title: {{$.Code}}
summary: {{$.Documentation.Summary}} {{$.RequiredLabels}} 
resources: 
permalink: /docs/{{$.Provider}}/{{$.Code}}/
nav_order: 2
parent: {{$.Provider | ToUpperProvider }} Checks
---

## {{$.Documentation.Summary}}

{{if $.Alias}}
Alias: {{ $.Alias }}
{{end}}

### Explanation

{{$.Documentation.Explanation}}

{{if $.Documentation.BadExample }}
### Insecure Example

The following example will fail the {{$.Code}} check.

{% highlight terraform %}
{{$.Documentation.BadExample}}
{% endhighlight %}

{{end}}
{{if $.Documentation.GoodExample }}
### Secure Example

The following example will pass the {{$.Code}} check.

{% highlight terraform %}
{{$.Documentation.GoodExample}}
{% endhighlight %}
{{end}}

### Related Links

{{range $link := $.Documentation.Links}}
- [{{.}}]({{.}}){:target="_blank" rel="nofollow noreferrer noopener"}
{{end}}
`
)

func generateWebPages(fileContents []*FileContent) error {
	for _, contents := range fileContents {
		for _, check := range contents.Checks {
			if err := generateWebPage(check); err != nil {
				return err
			}
		}
	}
	return generateDocsDataFile(fileContents)
}

var funcMap = template.FuncMap{
	"ToUpper":         strings.ToUpper,
	"ToUpperProvider": scanner.RuleProviderToString,
	"Join":            join,
}

func join(s []string) string {
	// first arg is sep, remaining args are strings to join
	if s == nil {
		return ""
	}
	return strings.Join(s[1:], s[0])
}

func generateDocsDataFile(contents []*FileContent) error {
	docsFilePath := fmt.Sprintf("%s/_data/docs.yml", webPath)
	if err := os.MkdirAll(filepath.Dir(docsFilePath), os.ModePerm); err != nil {
		return err
	}
	docTmpl := template.Must(template.New("web").Funcs(funcMap).Parse(docsDataFile))
	return writeTemplate(contents, docsFilePath, docTmpl)
}

func generateWebPage(check scanner.Check) error {
	webProviderPath := fmt.Sprintf("%s/docs/%s", webPath, strings.ToLower(string(check.Provider)))
	if err := os.MkdirAll(webProviderPath, os.ModePerm); err != nil {
		return err
	}

	filePath := fmt.Sprintf("%s/%s.md", webProviderPath, check.Code)

	fmt.Printf("Generating page for %s at %s\n", check.Code, filePath)
	webTmpl := template.Must(template.New("web").Funcs(funcMap).Parse(baseWebPageTemplate))
	return writeTemplate(check, filePath, webTmpl)
}

func writeTemplate(contents interface{}, path string, tmpl *template.Template) error {
	outputFile, err := os.Create(path)
	if err != nil {
		return err
	}
	defer func() { _ = outputFile.Close() }()
	return tmpl.Execute(outputFile, contents)
}
