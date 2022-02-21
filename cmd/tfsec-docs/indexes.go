package main

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"text/template"
)

func generateIndexPages(fileContents []*FileContent) error {

	provs := make(map[string]map[string][]templateObject)

	for _, fc := range fileContents {
		provServices := make(map[string][]templateObject)
		for _, c := range fc.Checks {

			if _, ok := provServices[c.Service]; !ok {
				provServices[c.Service] = make([]templateObject, 0)
			}

			provServices[c.Service] = append(provServices[c.Service], c)

		}
		provs[fc.Provider] = provServices
	}

	for p, ps := range provs {
		providerIndexPath := filepath.Join(webPath, strings.ToLower(p), "index.md")

		fmt.Printf("Generating index page for %s at %s\n", p, providerIndexPath)
		providerIndexTmpl := template.Must(template.New("providers").Funcs(funcMap).Parse(providerIndexPageTemplate))

		var services []serviceParts
		for s, checks := range ps {
			services = append(services, serviceParts{Name: s, Path: strings.ToLower(strings.ReplaceAll(s, " ", "-"))})

			fmt.Printf("Generating index page for %s at %s\n", p, providerIndexPath)
			serviceIndexTmpl := template.Must(template.New("service").Funcs(funcMap).Parse(serviceIndexPageTemplate))

			serviceIndexPath := filepath.Join(webPath, strings.ToLower(p), strings.ToLower(strings.ReplaceAll(s, " ", "-")), "index.md")

			sort.Slice(checks, func(i, j int) bool {
				return checks[i].ShortCode < checks[j].ShortCode
			})
			if err := writeTemplate(map[string]interface{}{
				"DisplayName": s,
				"Checks":      checks,
			}, serviceIndexPath, serviceIndexTmpl); err != nil {
				return err
			}
		}

		sort.Slice(services, func(i, j int) bool {
			return services[i].Name < services[j].Name
		})

		if err := writeTemplate(map[string]interface{}{
			"DisplayName": p,
			"Services":    services,
		}, providerIndexPath, providerIndexTmpl); err != nil {
			return err
		}
	}

	return nil
}

type serviceParts struct {
	Name string
	Path string
}

const providerIndexPageTemplate = `---
title: {{$.DisplayName}}
---

# {{$.DisplayName}}

## Services

{{range $link := $.Services}}
- [{{.Name}}]({{.Path}})
{{end}}

`

const serviceIndexPageTemplate = `---
title: {{$.DisplayName}}
---

# {{$.DisplayName}}

## Checks

{{range $link := $.Checks}}
- [{{.ShortCode}}]({{.ShortCode}}) {{.Summary}}
{{end}}


`
