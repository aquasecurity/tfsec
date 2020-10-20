package custom

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
	"os"
	"strings"
)

func Validate(checkFilePath string) error {
	if _, err := os.Stat(checkFilePath); os.IsNotExist(err) {
		return errors.New(fmt.Sprintf("check file could not be found at path %s", checkFilePath))
	}

	checkFile, err := loadCheckFile(checkFilePath)
	if err != nil {
		return err
	}

	var errorList []string
	for _, check := range checkFile.Checks {
		if err = func(check *Check) error {
			errs := validate(check)
			if len(errs) > 0 {
				jsonContent, err := json.MarshalIndent(check, "", "  ")
				if err != nil {
					return errors.New("check json is not valid")
				}
				errorStrings := getErrorStrings(errs)
				return errors.New(fmt.Sprintf("check failed with the following errors;\n\n - %s\n\n%s\n", errorStrings, jsonContent))
			}
			return nil
		}(check); err != nil {
			errorList = append(errorList, err.Error())
		}
	}
	if len(errorList) > 0 {
		return errors.New(strings.Join(errorList, "\n"))
	}
	return nil
}

func getErrorStrings(errs []error) string {
	var errorStrings []string
	for _, err := range errs {
		errorStrings = append(errorStrings, err.Error())
	}
	return strings.Join(errorStrings, "\n - ")
}

func validate(check *Check) []error {
	var checkErrors []error
	if len(check.Code) == 0 {
		checkErrors = append(checkErrors, errors.New("check.Code requires a value"))
	}
	if len(check.Description) == 0 {
		checkErrors = append(checkErrors, errors.New("check.Description requires a value"))
	}
	if !check.Severity.IsValid() {
		checkErrors = append(checkErrors, errors.New(fmt.Sprintf("check.Severity[%s] is not a recognised option. Should be %s", check.Severity, scanner.ValidSeverity)))
	}
	if len(check.RequiredTypes) == 0 {
		checkErrors = append(checkErrors, errors.New("check.RequiredTypes requires a value"))
	}
	if len(check.RequiredLabels) == 0 {
		checkErrors = append(checkErrors, errors.New("check.RequiredLabels requires a value"))
	}
	return validateMatchSpec(check.MatchSpec, check, checkErrors)
}

func validateMatchSpec(spec *MatchSpec, check *Check, checkErrors []error) []error {
	if !spec.Action.isValid() {
		checkErrors = append(checkErrors, errors.New(fmt.Sprintf("matchSpec.Action[%s] is not a recognised option. Should be %s", spec.Action, ValidCheckActions)))
	}
	// if the check is inModule, no name is required
	if len(spec.Name) == 0 && spec.Action != "inModule" {
		checkErrors = append(checkErrors, errors.New("matchSpec.Name requires a value"))
	}
	if spec.SubMatch != nil {
		return validateMatchSpec(spec.SubMatch, check, checkErrors)
	}
	return checkErrors
}
