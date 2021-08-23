package main

import (
	"fmt"
	"os"
	"strings"
	"text/template"

	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

const (
	baseWebPageTemplate = `---
title: {{$.DefSecCheck.Summary}}
shortcode: {{$.ID}}
legacy: {{$.LegacyID}}
summary: {{$.DefSecCheck.Summary}} 
resources: {{$.RequiredLabels}} 
permalink: /docs/{{$.Provider}}/{{$.Service}}/{{$.ShortCode}}/
redirect_from: 
  - /docs/{{$.Provider}}/{{$.LegacyID}}/
---

### Explanation

{{$.DefSecCheck.Explanation}}

### Possible Impact
{{$.DefSecCheck.Impact}}

### Suggested Resolution
{{$.DefSecCheck.Resolution}}

{{if $.BadExample }}
### Insecure Example

The following example will fail the {{$.ID}} check.

{% highlight terraform %}
{{ (index $.BadExample 0) }}
{% endhighlight %}

{{end}}
{{if $.GoodExample }}
### Secure Example

The following example will pass the {{$.ID}} check.

{% highlight terraform %}
{{ (index $.GoodExample 0) }}
{% endhighlight %}
{{end}}

{{if $.Links}}
### Provider Links

{{range $link := $.Links}}
- [{{.}}]({{.}}){:target="_blank" rel="nofollow noreferrer noopener"}
{{end}}
{{if $.DefSecCheck.Links}}
### General Links

{{range $link := $.DefSecCheck.Links}}
- [{{.}}]({{.}}){:target="_blank" rel="nofollow noreferrer noopener"}
{{end}}

{{end}}
`
)

func generateWebPages(fileContents []*FileContent) error {
	for _, contents := range fileContents {
		for _, check := range contents.Checks {
			webProviderPath := fmt.Sprintf("%s/docs/%s/%s", webPath, strings.ToLower(string(check.DefSecCheck.Provider)), strings.ToLower(check.DefSecCheck.Service))
			if err := generateWebPage(webProviderPath, check); err != nil {
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
	if s == nil {
		return ""
	}
	return strings.Join(s[1:], s[0])
}

func formatProviderName(providerName string) string {
	if providerName == "digitalocean" {
		providerName = "digital ocean"
	}
	return provider.Provider(providerName).DisplayName()
}

func generateWebPage(webProviderPath string, r rule.Rule) error {

	if err := os.MkdirAll(webProviderPath, os.ModePerm); err != nil {
		return err
	}
	filePath := fmt.Sprintf("%s/%s.md", webProviderPath, r.DefSecCheck.ShortCode)
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
