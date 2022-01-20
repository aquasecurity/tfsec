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

var matchFunctions = map[CheckAction]func(block.Block, *MatchSpec, *customContext) bool{
	IsPresent: func(block block.Block, spec *MatchSpec, customCtx *customContext) bool {
		return block.HasChild(spec.Name) || spec.IgnoreUndefined
	},
	NotPresent: func(block block.Block, spec *MatchSpec, customCtx *customContext) bool {
		return !block.HasChild(spec.Name)
	},
	IsEmpty: func(block block.Block, spec *MatchSpec, customCtx *customContext) bool {
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
	StartsWith: func(block block.Block, spec *MatchSpec, customCtx *customContext) bool {
		attribute := block.GetAttribute(spec.Name)
		if attribute.IsNil() {
			return spec.IgnoreUndefined
		}
		return attribute.StartsWith(processMatchValueVariables(spec.MatchValue, customCtx.variables))
	},
	EndsWith: func(block block.Block, spec *MatchSpec, customCtx *customContext) bool {
		attribute := block.GetAttribute(spec.Name)
		if attribute.IsNil() {
			return spec.IgnoreUndefined
		}
		return attribute.EndsWith(processMatchValueVariables(spec.MatchValue, customCtx.variables))
	},
	Contains: func(b block.Block, spec *MatchSpec, customCtx *customContext) bool {
		attribute := b.GetAttribute(spec.Name)
		if attribute.IsNil() {
			return spec.IgnoreUndefined
		}
		return attribute.Contains(processMatchValueVariables(spec.MatchValue, customCtx.variables), block.IgnoreCase)
	},
	NotContains: func(block block.Block, spec *MatchSpec, customCtx *customContext) bool {
		attribute := block.GetAttribute(spec.Name)
		if attribute.IsNil() {
			return spec.IgnoreUndefined
		}
		return !attribute.Contains(processMatchValueVariables(spec.MatchValue, customCtx.variables))
	},
	Equals: func(block block.Block, spec *MatchSpec, customCtx *customContext) bool {
		attribute := block.GetAttribute(spec.Name)
		if attribute.IsNil() {
			return spec.IgnoreUndefined
		}
		return attribute.Equals(processMatchValueVariables(spec.MatchValue, customCtx.variables))
	},
	NotEqual: func(block block.Block, spec *MatchSpec, customCtx *customContext) bool {
		attribute := block.GetAttribute(spec.Name)
		if attribute.IsNil() {
			return spec.IgnoreUndefined
		}
		return attribute.NotEqual(processMatchValueVariables(spec.MatchValue, customCtx.variables))
	},
	LessThan: func(block block.Block, spec *MatchSpec, customCtx *customContext) bool {
		attribute := block.GetAttribute(spec.Name)
		if attribute.IsNil() {
			return spec.IgnoreUndefined
		}
		return attribute.LessThan(processMatchValueVariables(spec.MatchValue, customCtx.variables))
	},
	LessThanOrEqualTo: func(block block.Block, spec *MatchSpec, customCtx *customContext) bool {
		attribute := block.GetAttribute(spec.Name)
		if attribute.IsNil() {
			return spec.IgnoreUndefined
		}
		return attribute.LessThanOrEqualTo(processMatchValueVariables(spec.MatchValue, customCtx.variables))
	},
	GreaterThan: func(block block.Block, spec *MatchSpec, customCtx *customContext) bool {
		attribute := block.GetAttribute(spec.Name)
		if attribute.IsNil() {
			return spec.IgnoreUndefined
		}
		return attribute.GreaterThan(processMatchValueVariables(spec.MatchValue, customCtx.variables))
	},
	GreaterThanOrEqualTo: func(block block.Block, spec *MatchSpec, customCtx *customContext) bool {
		attribute := block.GetAttribute(spec.Name)
		if attribute.IsNil() {
			return spec.IgnoreUndefined
		}
		return attribute.GreaterThanOrEqualTo(processMatchValueVariables(spec.MatchValue, customCtx.variables))
	},
	RegexMatches: func(block block.Block, spec *MatchSpec, customCtx *customContext) bool {
		attribute := block.GetAttribute(spec.Name)
		if attribute.IsNil() {
			return spec.IgnoreUndefined
		}
		return attribute.RegexMatches(processMatchValueVariables(spec.MatchValue, customCtx.variables))
	},
	IsAny: func(block block.Block, spec *MatchSpec, customCtx *customContext) bool {
		attribute := block.GetAttribute(spec.Name)
		return attribute != nil && attribute.IsAny(unpackInterfaceToInterfaceSlice(processMatchValueVariables(spec.MatchValue, customCtx.variables))...)
	},
	IsNone: func(block block.Block, spec *MatchSpec, customCtx *customContext) bool {
		attribute := block.GetAttribute(spec.Name)
		if attribute.IsNil() {
			return spec.IgnoreUndefined
		}
		return attribute.IsNone(unpackInterfaceToInterfaceSlice(processMatchValueVariables(spec.MatchValue, customCtx.variables))...)
	},
	RequiresPresence: func(block block.Block, spec *MatchSpec, customCtx *customContext) bool {
		return resourceFound(spec, customCtx.module)
	},
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
				RequiredTypes:   customCheck.RequiredTypes,
				RequiredLabels:  customCheck.RequiredLabels,
				RequiredSources: customCheck.RequiredSources,
				CheckTerraform: func(rootBlock block.Block, module block.Module) (results rules.Results) {
					matchSpec := customCheck.MatchSpec
					if !evalMatchSpec(rootBlock, matchSpec, NewCustomContext(module)) {
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

func evalMatchSpec(b block.Block, spec *MatchSpec, customCtx *customContext) bool {
	if b.IsNil() {
		return false
	}
	var evalResult bool

	for _, preCondition := range spec.PreConditions {
		clone := preCondition
		if !evalMatchSpec(b, &clone, customCtx) {
			// precondition not met
			return true
		}
	}

	switch spec.Action {
	case InModule:
		return b.InModule()
	case RegexMatches:
		if !matchFunctions[RegexMatches](b, spec, customCtx) {
			return spec.IgnoreUnmatched
		}
		evalResult = true
	case HasTag:
		return checkTags(b, spec, customCtx.module)
	case OfType:
		return ofType(b, spec)
	case Not:
		return notifyPredicate(b, spec, customCtx)
	case And:
		return processAndPredicate(spec, b, customCtx)
	case Or:
		return processOrPredicate(spec, b, customCtx)
	default:
		evalResult = matchFunctions[spec.Action](b, spec, customCtx)
	}

	if len(spec.AssignVariable) > 0 {
		customCtx.variables[spec.AssignVariable] = b.GetAttribute(spec.Name).AsStringValueOrDefault("", b).Value()
	}

	if spec.SubMatch != nil {
		evalResult = processSubMatches(spec, b, customCtx, evalResult)
	}

	return evalResult
}

func notifyPredicate(b block.Block, spec *MatchSpec, customCtx *customContext) bool {
	return !evalMatchSpec(b, &spec.PredicateMatchSpec[0], customCtx)
}

func processOrPredicate(spec *MatchSpec, b block.Block, customCtx *customContext) bool {
	for _, childSpec := range spec.PredicateMatchSpec {
		clone := childSpec
		if evalMatchSpec(b, &clone, customCtx) {
			return true
		}
	}
	return false
}

func processAndPredicate(spec *MatchSpec, b block.Block, customCtx *customContext) bool {
	set := make(map[bool]bool)

	for _, childSpec := range spec.PredicateMatchSpec {
		clone := childSpec
		result := evalMatchSpec(b, &clone, customCtx)
		set[result] = true

	}

	return len(set) == 1 && set[true]
}

func processSubMatches(spec *MatchSpec, b block.Block, customCtx *customContext, evalResult bool) bool {
	var subMatchTargets []block.Block
	switch spec.Action {
	case RequiresPresence:
		subMatchTargets = customCtx.module.GetResourcesByType(spec.Name)
	default:
		subMatchTargets = b.GetBlocks(spec.Name)
	}
	for _, b := range subMatchTargets {
		evalResult = evalMatchSpec(b, spec.SubMatch, customCtx)
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
