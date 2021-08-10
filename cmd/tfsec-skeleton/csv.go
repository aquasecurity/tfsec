package main

import (
	"encoding/csv"
	"fmt"
	"os"
	"strings"

	"github.com/aquasecurity/tfsec/cmd/tfsec-skeleton/examples"
	"github.com/aquasecurity/tfsec/cmd/tfsec-skeleton/requirements"
	"github.com/aquasecurity/tfsec/pkg/provider"
)

func generateFromCSV(path string) ([]*Input, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	reader := csv.NewReader(file)

	reader.FieldsPerRecord = 16

	rawCSVdata, err := reader.ReadAll()
	if err != nil {
		return nil, err
	}

	var inputs []*Input

	for i, record := range rawCSVdata {

		// not ready
		if record[0] != "1" {
			continue
		}

		// already done
		if record[1] == "1" {
			continue
		}

		var input Input
		input.Summary = record[2]
		input.Provider = provider.Provider(record[3])
		input.Service = record[4]
		input.ShortCode = record[5]
		input.RequiredTypes = []string{"resource"}
		input.RequiredLabels = strings.Split(record[6], ",")

		attrDotPath := record[7]
		pathParts := strings.Split(attrDotPath, ".")
		input.AttributeName = pathParts[len(pathParts)-1]
		comparison := record[8]
		value := convertToInterface(record[9])
		allowDefault := record[10] == "1" || record[10] == "TRUE"

		exampleCode := record[15]
		if exampleCode == "" {
			exampleCode, _ = examples.FindCode(string(input.Provider), input.RequiredTypes[0], input.RequiredLabels[0])
		}

		input.Severity = record[11]
		input.Impact = record[12]
		input.Resolution = record[13]
		input.Explanation = record[14]

		if comparison == "custom" {
			input.Requirement = requirements.Custom(
				input.RequiredTypes[0],
				input.RequiredLabels[0],
				exampleCode,
			)
		} else {
			comp := requirements.Comparison(comparison)
			if !comp.IsValid() {
				return nil, fmt.Errorf("invalid comparison '%s' on line %d", comparison, i)
			}

			input.Requirement = requirements.NewAttributeRequirement(
				input.RequiredTypes[0],
				input.RequiredLabels[0],
				attrDotPath,
				value,
				!allowDefault,
				exampleCode,
				comp,
			)
		}

		if err := input.Validate(); err != nil {
			return nil, fmt.Errorf("line %d [%s] of csv failed validation: %s", i, input.Summary, err)
		}

		inputs = append(inputs, &input)
	}

	return inputs, nil

}
