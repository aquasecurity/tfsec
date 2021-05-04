package main

import (
	"fmt"
	"os"
	"strings"
	"text/template"

	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

const (
	baseWebPageTemplate = `---
title: {{$.Code}} - {{$.Documentation.Summary}}
summary: {{$.Documentation.Summary}} 
resources: {{$.RequiredLabels}} 
permalink: /docs/{{$.Provider}}/{{$.Code}}/
---
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

{{if $.Documentation.Links}}
### Related Links

{{range $link := $.Documentation.Links}}
- [{{.}}]({{.}}){:target="_blank" rel="nofollow noreferrer noopener"}
{{end}}
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
	return nil
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
