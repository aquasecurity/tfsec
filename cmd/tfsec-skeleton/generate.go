package main

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"text/template"

	"github.com/liamg/clinch/prompt"
)

var providers = map[string]string{"AWS": "aws", "Azure": "azu", "GCP": "gcp", "Oracle": "oci", "General": "gen", "DigitalOcean": "dig", "GitHub": "git"}

type checkSkeleton struct {
	Provider         string
	ProviderLongName string
	CheckName        string
	ShortCode        string
	FullCode         string
	Service          string
	Summary          string
	Impact           string
	Resolution       string
	RequiredTypes    string
	RequiredLabels   string
	CheckFilename    string
	TestFileName     string
}

var funcMap = template.FuncMap{
	"ToUpper": strings.ToUpper,
}

func generateCheckBody() error {
	details, err := constructSkeleton()
	if err != nil {
		return err
	}
	checkTmpl := template.Must(template.New("check").Funcs(funcMap).Parse(checkTemplate))
	checkTestTmpl := template.Must(template.New("checkTest").Funcs(funcMap).Parse(checkTestTemplate))
	checkPath := fmt.Sprintf("internal/app/tfsec/rules/%s", details.CheckFilename)
	testPath := fmt.Sprintf("internal/app/tfsec/rules/%s", details.TestFileName)
	if err = verifyCheckPath(checkPath); err != nil {
		return err
	}
	if err = verifyCheckPath(testPath); err != nil {
		return err
	}
	if err = writeTemplate(checkPath, checkTmpl, details); err != nil {
		return err
	}
	if err = writeTemplate(testPath, checkTestTmpl, details); err != nil {
		return err
	}
	return nil
}

func writeTemplate(checkPath string, checkTmpl *template.Template, details *checkSkeleton) error {
	checkFile, err := os.Create(checkPath)
	if err != nil {
		return err
	}
	defer func() { _ = checkFile.Close() }()
	err = checkTmpl.Execute(checkFile, details)
	if err != nil {
		return err
	}

	return nil
}

func constructSkeleton() (*checkSkeleton, error) {
	var providerStrings []string
	for key := range providers {
		providerStrings = append(providerStrings, key)
	}

	sort.Slice(providerStrings, func(i, j int) bool {
		return providerStrings[i] < providerStrings[j]
	})

	_, selected, err := prompt.ChooseFromList("Select provider", providerStrings)
	if err != nil {
		return nil, err
	}

	service := prompt.EnterInput("Enter the service name, as see in terraform e.g. 'compute' for azurerm: ")
	shortCode := prompt.EnterInput("Enter very terse description e.g. 'enable disk encryption': ")
	summary := prompt.EnterInput("Enter a longer summary: ")
	impact := prompt.EnterInput("Enter a brief impact of not complying with check: ")
	resolution := prompt.EnterInput("Enter a brief resolution to pass check: ")
	blockTypes := prompt.EnterInput("Enter the supported block types: ")
	blockLabels := prompt.EnterInput("Enter the supported block labels: ")

	checkBody, err := populateSkeleton(summary, selected, service, shortCode, impact, resolution, blockTypes, blockLabels)
	if err != nil {
		return nil, err
	}

	return checkBody, nil
}

func populateSkeleton(summary, selected, service, shortCode, impact, resolution, blockTypes, blockLabels string) (*checkSkeleton, error) {
	checkBody := &checkSkeleton{}
	var err error
	checkBody.Summary = summary
	checkBody.ShortCode = shortCode
	checkBody.FullCode = strings.ToLower(fmt.Sprintf("%s-%s-%s", selected, service, shortCode))
	checkBody.Service = service
	checkBody.Impact = impact
	checkBody.Resolution = resolution
	checkBody.Provider = providers[selected]
	checkBody.ProviderLongName = selected

	if err != nil {
		return nil, err
	}

	checkBody.CheckName = fmt.Sprintf("%s%s", strings.Title(selected), strings.ReplaceAll(strings.Title(shortCode), "-", ""))
	checkBody.RequiredTypes = fmt.Sprintf("{\"%s\"}", strings.Join(strings.Split(blockTypes, " "), "\", \""))
	checkBody.RequiredLabels = fmt.Sprintf("{\"%s\"}", strings.Join(strings.Split(blockLabels, " "), "\", \""))
	filename := fmt.Sprintf("%s/%s/%s", selected, service, strings.ReplaceAll(shortCode, "-", "_"))
	checkBody.CheckFilename = fmt.Sprintf("%s_rule.go", strings.ToLower(filename))
	checkBody.TestFileName = fmt.Sprintf("%s_rule_test.go", strings.ToLower(filename))

	return checkBody, nil
}
