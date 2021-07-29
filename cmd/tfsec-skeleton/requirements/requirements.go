package requirements

import (
	"fmt"
	"strings"
)

type Requirement interface {
	GenerateGoodExample() string
	GenerateBadExample() string
	GenerateRuleCode() string
}

func sprintGo(value interface{}) string {
	if s, ok := value.(string); ok {
		return fmt.Sprintf("%q", s)
	}
	if s, ok := value.([]string); ok {
		return fmt.Sprintf(`"%s"`, strings.Join(s, `", "`))
	}
	return fmt.Sprintf("%v", value)
}

func createTerraformFromDotPath(dotPath string, value interface{}) string {

	var output string

	parts := strings.Split(dotPath, ".")

	for i, part := range parts {

		if i == len(parts)-1 {
			// attribute
			output += fmt.Sprintf("%s%s = %s\n", strings.Repeat("\t", i+1), part, sprintGo(value))
			break
		}

		// open block
		output += fmt.Sprintf("%s%s {\n", strings.Repeat("\t", i+1), part)
	}

	// close all blocks
	for i := len(parts) - 2; i >= 0; i-- {
		output += fmt.Sprintf("%s}\n", strings.Repeat("\t", i+1))
	}

	return output
}

func flipValue(value interface{}) interface{} {
	var badValue interface{}

	switch t := value.(type) {
	case bool:
		badValue = !t
	case string:
		switch t {
		case "on":
			badValue = "off"
		case "off":
			badValue = "on"
		case "yes":
			badValue = "no"
		case "no":
			badValue = "yes"
		default:
			badValue = "something"
		}
	case int:
		switch t {
		case 0:
			badValue = 1
		case 1:
			badValue = 0
		default:
			badValue = t + 1
		}
	}

	return badValue
}

func snakeToCamel(input string) string {
	var output string
	var upper bool
	for i, v := range input {
		if v == '_' {
			upper = true
			continue
		}
		if upper {
			output += strings.ToUpper(input[i : i+1])
			upper = false
			continue
		}
		output += strings.ToLower(input[i : i+1])
	}
	return output
}

func buildComparisonForValue(value interface{}, comparison Comparison) string {

	switch t := value.(type) {
	case []string:
		return buildStringSliceComparison(t, comparison)
	case int:
		return buildIntComparison(t, comparison)
	case string:
		return buildStringComparison(t, comparison)
	case bool:
		return buildBoolComparison(t, comparison)
	default:
		panic(fmt.Sprintf("Cannot do comparisons on type %T", t))
	}
}

func buildStringSliceComparison(values []string, comparison Comparison) string {
	switch comparison {
	case ComparisonAnyOf:
		return fmt.Sprintf(`IsAny(%s)`, sprintGo(values))
	case ComparisonNotAnyOf:
		return fmt.Sprintf(`IsNotAny(%s)`, sprintGo(values))
	}
	panic(fmt.Sprintf("Comparison '%s' not supported for string slice", comparison))
}

func buildStringComparison(value string, comparison Comparison) string {
	switch comparison {
	case ComparisonEquals:
		if value == "" {
			return "IsEmpty()"
		}
		return fmt.Sprintf(`Equals(%s)`, sprintGo(value))
	case ComparisonNotEquals:
		if value == "" {
			return "!IsEmpty()"
		}
		return fmt.Sprintf(`NotEqual(%s)`, sprintGo(value))
	}
	panic(fmt.Sprintf("Comparison '%s' not supported for string", comparison))
}

func buildIntComparison(value int, comparison Comparison) string {
	switch comparison {
	case ComparisonEquals:
		return fmt.Sprintf(`Equals(%s)`, sprintGo(value))
	case ComparisonNotEquals:
		return fmt.Sprintf(`NotEqual(%s)`, sprintGo(value))
	}
	panic(fmt.Sprintf("Comparison '%s' not supported for int", comparison))
}

func buildBoolComparison(value bool, comparison Comparison) string {
	switch comparison {
	case ComparisonEquals:
		if value {
			return "IsTrue()"
		}
		return "IsFalse()"
	case ComparisonNotEquals:
		if value {
			return "IsFalse()"
		}
		return "IsTrue()"
	}
	panic(fmt.Sprintf("Comparison '%s' not supported for bool", comparison))
}
