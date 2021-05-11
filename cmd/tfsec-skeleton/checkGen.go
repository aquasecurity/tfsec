package main

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"text/template"

	"github.com/liamg/clinch/prompt"
	"github.com/liamg/tml"
)

var providers = map[string]string{"AWS": "aws", "Azure": "azu", "GCP": "gcp", "Oracle": "oci", "General": "gen"}

type checkSkeleton struct {
	Provider         string
	ProviderLongName string
	CheckName        string
	ShortCode        string
	Code             string
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
	checkPath := fmt.Sprintf("internal/app/tfsec/checks/%s", details.CheckFilename)
	testPath := fmt.Sprintf("internal/app/tfsec/test/%s", details.TestFileName)
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
	tml.Printf("The new check has the code: %s%s\n", strings.ToUpper(details.Provider), details.Code)
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
	shortCodeContent := prompt.EnterInput("Enter very terse description: ")
	summary := prompt.EnterInput("Enter very slightly longer summary: ")
	impact := prompt.EnterInput("Enter a brief impact of not complying with check: ")
	resolution := prompt.EnterInput("Enter a brief resolution to pass check: ")
	blockTypes := prompt.EnterInput("Enter the supported block types: ")
	blockLabels := prompt.EnterInput("Enter the supported block labels: ")

	checkBody, err := populateSkeleton(summary, selected, shortCodeContent, impact, resolution, blockTypes, blockLabels)
	if err != nil {
		return nil, err
	}

	return checkBody, nil
}

func populateSkeleton(summary, selected, shortCodeContent, impact, resolution, blockTypes, blockLabels string) (*checkSkeleton, error) {
	checkBody := &checkSkeleton{}
	var err error
	checkBody.Summary = summary
	checkBody.Impact = impact
	checkBody.Resolution = resolution
	checkBody.Provider = providers[selected]
	checkBody.ProviderLongName = selected
	checkBody.Code, err = calculateNextCode(checkBody.Provider)
	if err != nil {
		return nil, err
	}

	checkBody.CheckName = fmt.Sprintf("%s%s", strings.ToUpper(checkBody.Provider), strings.ReplaceAll(strings.Title(shortCodeContent), " ", ""))
	checkBody.RequiredTypes = fmt.Sprintf("{\"%s\"}", strings.Join(strings.Split(blockTypes, " "), "\", \""))
	checkBody.RequiredLabels = fmt.Sprintf("{\"%s\"}", strings.Join(strings.Split(blockLabels, " "), "\", \""))
	filename := fmt.Sprintf("%s%s", checkBody.Provider, checkBody.Code)
	checkBody.CheckFilename = fmt.Sprintf("%s.go", strings.ToLower(filename))
	checkBody.TestFileName = fmt.Sprintf("%s_test.go", strings.ToLower(filename))

	return checkBody, nil
}
