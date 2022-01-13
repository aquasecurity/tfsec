package custom

import (
	"fmt"
	"regexp"

	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/debug"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

var matchFunctions = map[CheckAction]func(block.Block, *MatchSpec, map[string]string) bool{
	IsPresent: func(block block.Block, spec *MatchSpec, variables map[string]string) bool {
		return block.HasChild(spec.Name) || spec.IgnoreUndefined
	},
	NotPresent: func(block block.Block, spec *MatchSpec, variables map[string]string) bool {
		return !block.HasChild(spec.Name)
	},
	IsEmpty: func(block block.Block, spec *MatchSpec, variables map[string]string) bool {
		if block.MissingChild(spec.Name) {
			return true
		}

		attribute := block.GetAttribute(spec.Name)
		if attribute != nil {
			return attribute.IsEmpty()
		}
		childBlock := block.GetBlock(spec.Name)
		return childBlock.IsEmpty()
	},
	StartsWith: func(block block.Block, spec *MatchSpec, variables map[string]string) bool {
		attribute := block.GetAttribute(spec.Name)
		if attribute.IsNil() {
			return spec.IgnoreUndefined
		}
		return attribute.StartsWith(processMatchValueVariables(spec.MatchValue, variables))
	},
	EndsWith: func(block block.Block, spec *MatchSpec, variables map[string]string) bool {
		attribute := block.GetAttribute(spec.Name)
		if attribute.IsNil() {
			return spec.IgnoreUndefined
		}
		return attribute.EndsWith(processMatchValueVariables(spec.MatchValue, variables))
	},
	Contains: func(b block.Block, spec *MatchSpec, variables map[string]string) bool {
		attribute := b.GetAttribute(spec.Name)
		if attribute.IsNil() {
			return spec.IgnoreUndefined
		}
		return attribute.Contains(processMatchValueVariables(spec.MatchValue, variables), block.IgnoreCase)
	},
	NotContains: func(block block.Block, spec *MatchSpec, variables map[string]string) bool {
		attribute := block.GetAttribute(spec.Name)
		if attribute.IsNil() {
			return spec.IgnoreUndefined
		}
		return !attribute.Contains(processMatchValueVariables(spec.MatchValue, variables))
	},
	Equals: func(block block.Block, spec *MatchSpec, variables map[string]string) bool {
		attribute := block.GetAttribute(spec.Name)
		if attribute.IsNil() {
			return spec.IgnoreUndefined
		}
		return attribute.Equals(processMatchValueVariables(spec.MatchValue, variables))
	},
	NotEqual: func(block block.Block, spec *MatchSpec, variables map[string]string) bool {
		attribute := block.GetAttribute(spec.Name)
		if attribute.IsNil() {
			return spec.IgnoreUndefined
		}
		return attribute.NotEqual(processMatchValueVariables(spec.MatchValue, variables))
	},
	LessThan: func(block block.Block, spec *MatchSpec, variables map[string]string) bool {
		attribute := block.GetAttribute(spec.Name)
		if attribute.IsNil() {
			return spec.IgnoreUndefined
		}
		return attribute.LessThan(processMatchValueVariables(spec.MatchValue, variables))
	},
	LessThanOrEqualTo: func(block block.Block, spec *MatchSpec, variables map[string]string) bool {
		attribute := block.GetAttribute(spec.Name)
		if attribute.IsNil() {
			return spec.IgnoreUndefined
		}
		return attribute.LessThanOrEqualTo(processMatchValueVariables(spec.MatchValue, variables))
	},
	GreaterThan: func(block block.Block, spec *MatchSpec, variables map[string]string) bool {
		attribute := block.GetAttribute(spec.Name)
		if attribute.IsNil() {
			return spec.IgnoreUndefined
		}
		return attribute.GreaterThan(processMatchValueVariables(spec.MatchValue, variables))
	},
	GreaterThanOrEqualTo: func(block block.Block, spec *MatchSpec, variables map[string]string) bool {
		attribute := block.GetAttribute(spec.Name)
		if attribute.IsNil() {
			return spec.IgnoreUndefined
		}
		return attribute.GreaterThanOrEqualTo(processMatchValueVariables(spec.MatchValue, variables))
	},
	RegexMatches: func(block block.Block, spec *MatchSpec, variables map[string]string) bool {
		attribute := block.GetAttribute(spec.Name)
		if attribute.IsNil() {
			return spec.IgnoreUndefined
		}
		return attribute.RegexMatches(processMatchValueVariables(spec.MatchValue, variables))
	},
	IsAny: func(block block.Block, spec *MatchSpec, variables map[string]string) bool {
		attribute := block.GetAttribute(spec.Name)
		return attribute != nil && attribute.IsAny(unpackInterfaceToInterfaceSlice(processMatchValueVariables(spec.MatchValue, variables))...)
	},
	IsNone: func(block block.Block, spec *MatchSpec, variables map[string]string) bool {
		attribute := block.GetAttribute(spec.Name)
		if attribute.IsNil() {
			return spec.IgnoreUndefined
		}
		return attribute.IsNone(unpackInterfaceToInterfaceSlice(processMatchValueVariables(spec.MatchValue, variables))...)
	},
	RequiresPresence: func(block block.Block, spec *MatchSpec, module block.Module) bool { return resourceFound(spec, module) },
}

func processFoundChecks(checks ChecksFile) {
	for _, customCheck := range checks.Checks {
		func(customCheck Check) {
			debug.Log("Loading check: %s\n", customCheck.Code)
			scanner.RegisterCheckRule(rule.Rule{
				Base: rules.Register(
					rules.Rule{
						Service:    "custom",
						ShortCode:  customCheck.Code,
						Summary:    customCheck.Description,
						Impact:     customCheck.Impact,
						Resolution: customCheck.Resolution,
						Provider:   provider.CustomProvider,
						Links:      customCheck.RelatedLinks,
						Severity:   customCheck.Severity,
					},
					nil,
				),
				LegacyID:        customCheck.Code,
				RequiredTypes:   customCheck.RequiredTypes,
				RequiredLabels:  customCheck.RequiredLabels,
				RequiredSources: customCheck.RequiredSources,
				CheckTerraform: func(rootBlock block.Block, module block.Module) (results rules.Results) {
					matchSpec := customCheck.MatchSpec
					if !evalMatchSpec(rootBlock, matchSpec, module, nil) {
						results.Add(
							fmt.Sprintf("Custom check failed for resource %s. %s", rootBlock.FullName(), customCheck.ErrorMessage),
							rootBlock,
						)
					}
					return
				},
			})
		}(*customCheck)
	}
}

func evalMatchSpec(b block.Block, spec *MatchSpec, module block.Module, variables map[string]string) bool {
	if variables == nil {
		variables = make(map[string]string)
	}
	if b.IsNil() {
		return false
	}
	var evalResult bool

	for _, preCondition := range spec.PreConditions {
		clone := preCondition
		if !evalMatchSpec(b, &clone, module, variables) {
			// precondition not met
			return true
		}
	}

	switch spec.Action {
	case InModule:
		return b.InModule()
	case RegexMatches:
		if !matchFunctions[RegexMatches](b, spec, variables) {
			return spec.IgnoreUnmatched
		}
		evalResult = true
	case HasTag:
		return checkTags(b, spec, module)
	case OfType:
		return ofType(b, spec)
	case Not:
		return notifyPredicate(b, spec, module, variables)
	case And:
		return processAndPredicate(spec, b, module, variables)
	case Or:
		return processOrPredicate(spec, b, module, variables)
	default:
		evalResult = matchFunctions[spec.Action](b, spec, variables)
	}

	if len(spec.AssignVariable) > 0 {
		variables[spec.AssignVariable] = b.GetAttribute(spec.Name).AsStringValueOrDefault("", b).Value()
	}

	if spec.SubMatch != nil {
		evalResult = processSubMatches(spec, b, module, variables, evalResult)
	}

	return evalResult
}

func notifyPredicate(b block.Block, spec *MatchSpec, module block.Module, variables map[string]string) bool {
	return !evalMatchSpec(b, &spec.PredicateMatchSpec[0], module, variables)
}

func processOrPredicate(spec *MatchSpec, b block.Block, module block.Module, variables map[string]string) bool {
	for _, childSpec := range spec.PredicateMatchSpec {
		clone := childSpec
		if evalMatchSpec(b, &clone, module, variables) {
			return true
		}
	}
	return false
}

func processAndPredicate(spec *MatchSpec, b block.Block, module block.Module, variables map[string]string) bool {
	set := make(map[bool]bool)

	for _, childSpec := range spec.PredicateMatchSpec {
		clone := childSpec
		result := evalMatchSpec(b, &clone, module, variables)
		set[result] = true

	}

	return len(set) == 1 && set[true]
}

func processSubMatches(spec *MatchSpec, b block.Block, module block.Module, variables map[string]string, evalResult bool) bool {
	for _, b := range b.GetBlocks(spec.Name) {
		evalResult = evalMatchSpec(b, spec.SubMatch, nil, variables)
		if !evalResult {
			break
		}
	}

	return evalResult
}

func processMatchValueVariables(matchValue interface{}, variables map[string]string) interface{} {
	switch matchValue.(type) {
	case string:
		matchValueString := fmt.Sprintf("%v", matchValue)
		re := regexp.MustCompile(`TFSEC_VAR_[A-Z_]+`)
		return re.ReplaceAllStringFunc(matchValueString, func(match string) string {
			return variables[match]
		})
	default:
		return matchValue
	}
}

func resourceFound(spec *MatchSpec, module block.Module) bool {
	val := fmt.Sprintf("%v", spec.Name)
	byType := module.GetResourcesByType(val)
	return len(byType) > 0
}

func unpackInterfaceToInterfaceSlice(t interface{}) []interface{} {
	switch t := t.(type) {
	case []interface{}:
		return t
	}
	return nil
}
