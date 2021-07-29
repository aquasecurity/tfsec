package requirements

import (
	"fmt"
	"strings"

	"github.com/aquasecurity/tfsec/cmd/tfsec-skeleton/examples"
)

func AttributeMustHaveValue(blockType string, blockLabel string, dotPath string, expectedValue interface{}, failCheckForDefaultValue bool, exampleCode string) Requirement {
	return NewAttributeRequirement(blockType, blockLabel, dotPath, expectedValue, failCheckForDefaultValue, exampleCode, ComparisonEquals)
}

func AttributeMustNotHaveValue(blockType string, blockLabel string, dotPath string, expectedValue interface{}, failCheckForDefaultValue bool, exampleCode string) Requirement {
	return NewAttributeRequirement(blockType, blockLabel, dotPath, expectedValue, failCheckForDefaultValue, exampleCode, ComparisonNotEquals)
}

type attributeBase struct {
	dotPath                  string
	value                    interface{}
	comparison               Comparison
	failCheckForDefaultValue bool
	blockType                string
	blockLabel               string
	exampleCode              string
}

func NewAttributeRequirement(blockType string, blockLabel string, dotPath string, value interface{}, failCheckForDefaultValue bool, exampleCode string, comparison Comparison) Requirement {
	var req attributeBase
	req.dotPath = dotPath
	req.value = value
	req.comparison = comparison
	req.failCheckForDefaultValue = failCheckForDefaultValue
	req.blockType = blockType
	req.blockLabel = blockLabel
	req.exampleCode = exampleCode
	return &req
}

func (a *attributeBase) GenerateGoodExample() string {

	var value interface{}

	switch a.comparison {
	case ComparisonEquals:
		value = a.value
	case ComparisonNotEquals:
		value = flipValue(a.value)
	case ComparisonAnyOf:
		if strs, ok := a.value.([]string); ok && len(strs) > 0 {
			value = strs[0]
		} else {
			panic("only non-zero length list of strings are supported")
		}
	case ComparisonNotAnyOf:
		value = "something"
	case ComparisonGreaterThan:
		if i, ok := a.value.(int); ok {
			value = i + 1
		} else {
			panic(fmt.Sprintf("comparison '%s' cannot support value %#v", a.comparison, a.value))
		}
	case ComparisonLessThan:
		if i, ok := a.value.(int); ok {
			value = i - 1
		} else {
			panic(fmt.Sprintf("comparison '%s' cannot support value %#v", a.comparison, a.value))
		}
	case ComparisonGreaterThanOrEqual:
		if i, ok := a.value.(int); ok {
			value = i
		} else {
			panic(fmt.Sprintf("comparison '%s' cannot support value %#v", a.comparison, a.value))
		}
	case ComparisonLessThanOrEqual:
		if i, ok := a.value.(int); ok {
			value = i
		} else {
			panic(fmt.Sprintf("comparison '%s' cannot support value %#v", a.comparison, a.value))
		}
	default:
		panic(fmt.Sprintf("comparison '%s' is not supported", a.comparison))
	}

	if a.exampleCode != "" {
		return examples.SetAttribute(a.exampleCode, fmt.Sprintf("%s.%s.*.%s", a.blockType, a.blockLabel, a.dotPath), value, "good_example")
	}

	return fmt.Sprintf(`
%s "%s" "%s" {
%s}
`, a.blockType, a.blockLabel, "good_example", createTerraformFromDotPath(a.dotPath, value))
}

func (a *attributeBase) GenerateBadExample() string {

	var value interface{}

	switch a.comparison {
	case ComparisonEquals:
		value = flipValue(a.value)
	case ComparisonNotEquals:
		value = a.value
	case ComparisonAnyOf:
		value = "something"
	case ComparisonNotAnyOf:
		if strs, ok := a.value.([]string); ok && len(strs) > 0 {
			value = strs[0]
		} else {
			panic("only non-zero length list of strings are supported")
		}
	case ComparisonGreaterThan:
		if i, ok := a.value.(int); ok {
			value = i - 1
		} else {
			panic(fmt.Sprintf("comparison '%s' cannot support value %#v", a.comparison, a.value))
		}
	case ComparisonLessThan:
		if i, ok := a.value.(int); ok {
			value = i + 1
		} else {
			panic(fmt.Sprintf("comparison '%s' cannot support value %#v", a.comparison, a.value))
		}
	case ComparisonGreaterThanOrEqual:
		if i, ok := a.value.(int); ok {
			value = i - 1
		} else {
			panic(fmt.Sprintf("comparison '%s' cannot support value %#v", a.comparison, a.value))
		}
	case ComparisonLessThanOrEqual:
		if i, ok := a.value.(int); ok {
			value = i + 1
		} else {
			panic(fmt.Sprintf("comparison '%s' cannot support value %#v", a.comparison, a.value))
		}
	default:
		panic(fmt.Sprintf("comparison'%s' is not supported", a.comparison))
	}

	if a.exampleCode != "" {
		return examples.SetAttribute(a.exampleCode, fmt.Sprintf("%s.%s.*.%s", a.blockType, a.blockLabel, a.dotPath), value, "bad_example")
	}

	return fmt.Sprintf(`
%s "%s" "%s" {
%s}
`, a.blockType, a.blockLabel, "bad_example", createTerraformFromDotPath(a.dotPath, value))
}

func (a *attributeBase) GenerateRuleCode() string {
	var code string

	lowestBlock := "resourceBlock"
	parts := strings.Split(a.dotPath, ".")

	getBlockCode := lowestBlock

	for i, part := range parts {
		if i == len(parts)-1 {
			break
		}
		getBlockCode = fmt.Sprintf(`%s.GetBlock("%s")`, getBlockCode, part)
	}

	attrName := parts[len(parts)-1]
	attrVarName := snakeToCamel(attrName) + "Attr"

	code += fmt.Sprintf(`if %s := %s.GetAttribute("%s"); `, attrVarName, getBlockCode, attrName)

	if a.failCheckForDefaultValue {
		code += fmt.Sprintf(`%s.IsNil() { // alert on use of default value
				set.AddResult().
					WithDescription("Resource '%%s' uses default value for %s", resourceBlock.FullName())
			} else if `, attrVarName, a.dotPath)
	}

	var messageTemplate string

	switch a.comparison {
	case ComparisonEquals:
		messageTemplate = fmt.Sprintf("Resource '%%s' does not have %s set to %v", a.dotPath, a.value)
	case ComparisonNotEquals:
		messageTemplate = fmt.Sprintf("Resource '%%s' has %s set to %v", a.dotPath, a.value)
	case ComparisonAnyOf:
		messageTemplate = fmt.Sprintf("Resource '%%s' does not have %s set to one of %s", a.dotPath, a.value)
	case ComparisonNotAnyOf:
		messageTemplate = fmt.Sprintf("Resource '%%s' has %s set to one of %s", a.dotPath, a.value)
	case ComparisonGreaterThan:
		messageTemplate = fmt.Sprintf("Resource '%%s' does not have %s set to greater than %d", a.dotPath, a.value)
	case ComparisonLessThan:
		messageTemplate = fmt.Sprintf("Resource '%%s' does not have %s set to less than %d", a.dotPath, a.value)
	case ComparisonGreaterThanOrEqual:
		messageTemplate = fmt.Sprintf("Resource '%%s' does not have %s set to greater than or equal to %d", a.dotPath, a.value)
	case ComparisonLessThanOrEqual:
		messageTemplate = fmt.Sprintf("Resource '%%s' does not have %s set to greater than or equal to %d", a.dotPath, a.value)
	default:
		panic(fmt.Sprintf("comparison '%s' is not supported", a.comparison))
	}

	code += fmt.Sprintf(`%s.%s {
				set.AddResult().
					WithDescription("%s", resourceBlock.FullName()).
					WithAttribute(%s)
			}`, attrVarName, buildComparisonForValue(a.value, a.comparison.Reverse()), messageTemplate, attrVarName)

	return code
}
