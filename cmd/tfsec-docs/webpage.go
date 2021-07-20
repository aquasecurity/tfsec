package main

import (
	"fmt"
	"os"
	"strings"
	"text/template"

	"github.com/aquasecurity/tfsec/pkg/rule"
)

const (
	baseWebPageTemplate = `---
title: {{$.ID}} - {{$.Documentation.Summary}}
summary: {{$.Documentation.Summary}} 
resources: {{$.RequiredLabels}} 
permalink: /docs/{{$.Provider}}/{{$.ID}}/
---
### Explanation

{{$.Documentation.Explanation}}

### Possible Impact
{{$.Documentation.Impact}}

### Suggested Resolution
{{$.Documentation.Resolution}}

{{if $.Documentation.BadExample }}
### Insecure Example

The following example will fail the {{$.ID}} check.

{% highlight terraform %}
{{$.Documentation.BadExample}}
{% endhighlight %}

{{end}}
{{if $.Documentation.GoodExample }}
### Secure Example

The following example will pass the {{$.ID}} check.

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
			webProviderPath := fmt.Sprintf("%s/docs/%s/%s", webPath, strings.ToLower(string(check.Provider)), strings.ToLower(check.Service))
			if err := generateWebPage(webProviderPath, check, false); err != nil {
				return err
			}
			webProviderPath = fmt.Sprintf("%s/docs/%s", webPath, strings.ToLower(string(check.Provider)))
			if err := generateWebPage(webProviderPath, check, true); err != nil {
				return err
			}
		}
	}
	return nil
}

var funcMap = template.FuncMap{
	"ToUpper":            strings.ToUpper,
	"FormatProviderName": formatProviderName,
	"Join":               join,
}

func join(s []string) string {
	// first arg is sep, remaining args are strings to join
	if s == nil {
		return ""
	}
	return strings.Join(s[1:], s[0])
}

func formatProviderName(providerName string) string {
	if providerName == "digitalocean" {
		providerName = "digital ocean"
	}
	switch providerName {
	case "aws":
		return strings.ToUpper(providerName)
	default:
		return strings.Title(strings.ToLower(providerName))
	}
}

func generateWebPage(webProviderPath string, r rule.Rule, legacy bool) error {

	if err := os.MkdirAll(webProviderPath, os.ModePerm); err != nil {
		return err
	}
	filePath := fmt.Sprintf("%s/%s.md", webProviderPath, r.ID())
	if legacy {
		if r.LegacyID == "" {
			return nil
		}
		filePath = fmt.Sprintf("%s/%s.md", webProviderPath, r.LegacyID)
	}

	fmt.Printf("Generating page for %s at %s\n", r.ID(), filePath)
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
