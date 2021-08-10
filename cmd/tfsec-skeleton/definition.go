package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/aquasecurity/tfsec/cmd/tfsec-skeleton/requirements"
)

type Definition struct {
	*Input
	TestName        string
	CheckFilename   string
	TestFileName    string
	Package         string
	BadExampleCode  string
	GoodExampleCode string
	FirstLink       string
	RuleCode        string
	Requirements    []requirements.Requirement
}

func writeRuleFromInput(input *Input, forceOverwrite bool) error {
	definition := Definition{
		Input: input,
	}

	definition.TestName = fmt.Sprintf("%s%s", definition.Provider.ConstName(), strings.ReplaceAll(strings.Title(definition.ShortCode), "-", ""))
	definition.Package = strings.ReplaceAll(definition.Service, "-", "")
	definition.FirstLink = findDocLink(string(definition.Provider), definition.RequiredTypes[0], definition.RequiredLabels[0], input.AttributeName)

	definition.BadExampleCode = definition.Requirement.GenerateBadExample()
	definition.GoodExampleCode = definition.Requirement.GenerateGoodExample()
	definition.RuleCode = definition.Requirement.GenerateRuleCode()

	filename := fmt.Sprintf("%s/%s/%s", definition.Provider, definition.Package, strings.ReplaceAll(definition.ShortCode, "-", "_"))
	definition.CheckFilename = fmt.Sprintf("%s_rule.go", strings.ToLower(filename))
	definition.TestFileName = fmt.Sprintf("%s_rule_test.go", strings.ToLower(filename))

	checkTmpl := template.Must(template.New("check").Parse(checkTemplate))
	checkTestTmpl := template.Must(template.New("checkTest").Parse(checkTestTemplate))
	checkPath := fmt.Sprintf("internal/app/tfsec/rules/%s", definition.CheckFilename)
	testPath := fmt.Sprintf("internal/app/tfsec/rules/%s", definition.TestFileName)

	if err := os.MkdirAll(filepath.Dir(checkPath), 0700); err != nil {
		return err
	}

	if err := verifyPathDoesNotExist(checkPath, forceOverwrite); err != nil {
		return err
	}
	if err := verifyPathDoesNotExist(testPath, forceOverwrite); err != nil {
		return err
	}

	if err := writeTemplate(checkPath, checkTmpl, definition); err != nil {
		return err
	}
	if err := writeTemplate(testPath, checkTestTmpl, definition); err != nil {
		return err
	}

	return nil
}
