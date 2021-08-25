package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/aquasecurity/tfsec/pkg/rule"
	"gopkg.in/yaml.v2"
)

const navDocsTemplate = `---
- title: Getting Started
  state: open
  docs:
  - installation
  - usage

||CHECKBLOCK||

- title: Config
  state: open
  docs:
    - config
    - custom-checks
    
- title: GitHub Actions
  state: open
  docs:
    - github-action
    - pr-commenter
`

type providerChecks struct {
	Title     string      `yaml:"title"`
	Providers []*navBlock `yaml:"providers"`
}

type navBlock struct {
	Title    string    `yaml:"title"`
	Provider string    `yaml:"provider"`
	Services []service `yaml:"services"`
}

type service struct {
	Title   string   `yaml:"title"`
	Service string   `yaml:"service"`
	Docs    []string `yaml:"docs"`
}

func generateNavIndexFile(registeredChecks []*FileContent) error {
	var navBlocks []*navBlock

	for _, check := range registeredChecks {
		block := &navBlock{
			Title:    formatProviderName(check.Provider),
			Services: getServices(check.Checks, check.Provider),
			Provider: fmt.Sprintf("%s/", check.Provider),
		}

		navBlocks = append(navBlocks, block)
	}

	sort.Slice(navBlocks, func(i, j int) bool {
		return navBlocks[i].Title < navBlocks[j].Title
	})

	topLevel := &[]providerChecks{
		{
			Title:     "Provider Checks",
			Providers: navBlocks,
		},
	}

	content, err := yaml.Marshal(topLevel)
	if err != nil {
		panic(err)
	}
	providerFilePath := fmt.Sprintf("%s/data/navigation_docs.yml", webPath)
	if err := os.MkdirAll(filepath.Dir(providerFilePath), os.ModePerm); err != nil {
		return err
	}

	navDocs := strings.ReplaceAll(navDocsTemplate, "||CHECKBLOCK||", string(content))

	file, err := os.Create(providerFilePath)
	if err != nil {
		panic(err)
	}

	_, err = file.Write([]byte(navDocs))
	return err
}

func getServices(checks []rule.Rule, provider string) []service {
	var services []service
	mappings := make(map[string][]string)

	for _, check := range checks {
		mappings[check.Base.Rule().Service] = append(mappings[check.Base.Rule().Service], fmt.Sprintf("%s/%s/%s", check.Base.Rule().Provider, check.Base.Rule().Service, check.Base.Rule().ShortCode))
	}

	for k, mapping := range mappings {
		sort.Strings(mapping)
		services = append(services, service{
			Title:   k,
			Service: fmt.Sprintf("%s/%s", provider, k),
			Docs:    mapping,
		})
	}

	sort.Slice(services, func(i, j int) bool {
		return services[i].Service < services[j].Service
	})
	return services
}
