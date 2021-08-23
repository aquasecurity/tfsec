package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"strings"

	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/tfsec/cmd/tfsec-skeleton/examples"
	"github.com/aquasecurity/tfsec/cmd/tfsec-skeleton/requirements"
	"github.com/liamg/clinch/prompt"
)

func (input *Input) trySwap() error {
	if swapExists() {
		if inputYesNo("Swap file found! Would you like to continue your progress?") {
			loaded, err := loadFromSwap()
			if err != nil {
				return err
			}
			*input = *loaded
			fmt.Println("Swap file loaded!")
		}
	}
	return nil
}

func (input *Input) readInitialInputs() error {

	if input.Provider == "" {
		_, providerStr, err := prompt.ChooseFromList("Select provider:", providers)
		if err != nil {
			return err
		}
		input.Provider = provider.Provider(providerStr)
		saveSwapFile(input)
	}

	if input.Service == "" {
		input.Service = prompt.EnterInput("Enter the service name, as seen in terraform e.g. 'compute' for azurerm: ")
		saveSwapFile(input)
	}

	if input.ShortCode == "" {
		input.ShortCode = prompt.EnterInput("Enter very terse description e.g. 'enable disk encryption': ")
		saveSwapFile(input)
	}

	if input.Summary == "" {
		input.Summary = prompt.EnterInput("Enter a longer summary: ")
		saveSwapFile(input)
	}

	if input.Explanation == "" {
		input.Explanation = prompt.EnterInput("Enter an explanation: ")
		saveSwapFile(input)
	}

	if input.Impact == "" {
		input.Impact = prompt.EnterInput("Enter a brief impact of not complying with check: ")
		saveSwapFile(input)
	}

	if input.Resolution == "" {
		input.Resolution = prompt.EnterInput("Enter a brief resolution to pass check: ")
		saveSwapFile(input)
	}

	if input.Severity == "" {
		_, severityStr, err := prompt.ChooseFromList("Which severity should be used?", []string{"Critical", "High", "Medium", "Low"})
		if err != nil {
			return err
		}
		input.Severity = severityStr
		saveSwapFile(input)
	}

	if len(input.RequiredTypes) == 0 {
		blockTypes := prompt.EnterInput("Enter the supported block types (e.g. resource): ")
		input.RequiredTypes = strings.Split(blockTypes, ",")
		saveSwapFile(input)
	}
	if len(input.RequiredLabels) == 0 {
		blockLabels := prompt.EnterInput("Enter the supported block labels (e.g. aws_s3_bucket: ")
		input.RequiredLabels = strings.Split(blockLabels, ",")
		saveSwapFile(input)
	}

	return nil
}

func (input *Input) gatherInputsInteractively() error {

	if err := input.trySwap(); err != nil {
		return err
	}

	if err := input.readInitialInputs(); err != nil {
		return err
	}

	requirementTypes := []requirements.Comparison{
		requirements.ComparisonEquals,
		requirements.ComparisonNotEquals,
		requirements.ComparisonAnyOf,
		requirements.ComparisonNotAnyOf,
		requirements.ComparisonGreaterThan,
		requirements.ComparisonLessThan,
		requirements.ComparisonGreaterThanOrEqual,
		requirements.ComparisonLessThanOrEqual,
	}

	var requirementStrs []string
	for _, comparison := range requirementTypes {
		requirementStrs = append(requirementStrs, string(comparison))
	}
	requirementStrs = append(requirementStrs, "custom")

	requirementIndex, _, err := prompt.ChooseFromList("Which comparison does your rule involve?", requirementStrs)
	if err != nil {
		return err
	}

	exampleCode, _ := examples.FindCode(string(input.Provider), input.RequiredTypes[0], input.RequiredLabels[0])

	if requirementIndex == len(requirementStrs)-1 {
		input.Requirement = requirements.Custom(input.RequiredTypes[0], input.RequiredLabels[0], exampleCode)
	} else {
		input.AttributeName = prompt.EnterInput("Enter the path to the attribute to check (e.g. settings.encryption.enabled): ")
		expectedValue := enterInterfaceValue("Enter the value the attribute must have to pass the check (e.g. true): ")
		failForDefault := inputYesNo("Should the check fail if a default value is used?")
		input.Requirement = requirements.NewAttributeRequirement(input.RequiredTypes[0], input.RequiredLabels[0], input.AttributeName, expectedValue, failForDefault, exampleCode, requirementTypes[requirementIndex])
	}

	_ = deleteSwap()

	if err := input.Validate(); err != nil {
		return err
	}

	return nil
}

func swapPath() string {
	return path.Join(os.TempDir(), "tfsec.swp")
}

func deleteSwap() error {
	return os.Remove(swapPath())
}

func swapExists() bool {
	_, err := os.Stat(swapPath())
	return err == nil || !os.IsNotExist(err)
}

func loadFromSwap() (*Input, error) {
	data, err := ioutil.ReadFile(swapPath())
	if err != nil {
		return nil, err
	}
	var input Input
	if err := json.Unmarshal(data, &input); err != nil {
		return nil, err
	}
	return &input, nil
}

func saveSwapFile(input *Input) error {
	data, err := json.Marshal(input)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(swapPath(), data, 0600)
}
