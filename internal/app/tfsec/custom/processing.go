package custom

import (
	"fmt"

	"github.com/aquasecurity/tfsec/pkg/provider"
	"github.com/aquasecurity/tfsec/pkg/severity"

	"github.com/aquasecurity/tfsec/pkg/result"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/debug"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

var matchFunctions = map[CheckAction]func(block.Block, *MatchSpec) bool{
	IsPresent: func(block block.Block, spec *MatchSpec) bool {
		return block.HasChild(spec.Name) || spec.IgnoreUndefined
	},
	NotPresent: func(block block.Block, spec *MatchSpec) bool { return !block.HasChild(spec.Name) },
	IsEmpty: func(block block.Block, spec *MatchSpec) bool {
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
	StartsWith: func(block block.Block, spec *MatchSpec) bool {
		attribute := block.GetAttribute(spec.Name)
		if attribute.IsNil() {
			return spec.IgnoreUndefined
		}
		return attribute.StartsWith(spec.MatchValue)
	},
	EndsWith: func(block block.Block, spec *MatchSpec) bool {
		attribute := block.GetAttribute(spec.Name)
		if attribute.IsNil() {
			return spec.IgnoreUndefined
		}
		return attribute.EndsWith(spec.MatchValue)
	},
	Contains: func(b block.Block, spec *MatchSpec) bool {
		attribute := b.GetAttribute(spec.Name)
		if attribute.IsNil() {
			return spec.IgnoreUndefined
		}
		return attribute.Contains(spec.MatchValue, block.IgnoreCase)
	},
	NotContains: func(block block.Block, spec *MatchSpec) bool {
		attribute := block.GetAttribute(spec.Name)
		if attribute.IsNil() {
			return spec.IgnoreUndefined
		}
		return !attribute.Contains(spec.MatchValue)
	},
	Equals: func(block block.Block, spec *MatchSpec) bool {
		attribute := block.GetAttribute(spec.Name)
		if attribute.IsNil() {
			return spec.IgnoreUndefined
		}
		return attribute.Equals(spec.MatchValue)
	},
	NotEqual: func(block block.Block, spec *MatchSpec) bool {
		attribute := block.GetAttribute(spec.Name)
		if attribute.IsNil() {
			return spec.IgnoreUndefined
		}
		return attribute.NotEqual(spec.MatchValue)
	},
	LessThan: func(block block.Block, spec *MatchSpec) bool {
		attribute := block.GetAttribute(spec.Name)
		if attribute.IsNil() {
			return spec.IgnoreUndefined
		}
		return attribute.LessThan(spec.MatchValue)
	},
	LessThanOrEqualTo: func(block block.Block, spec *MatchSpec) bool {
		attribute := block.GetAttribute(spec.Name)
		if attribute.IsNil() {
			return spec.IgnoreUndefined
		}
		return attribute.LessThanOrEqualTo(spec.MatchValue)
	},
	GreaterThan: func(block block.Block, spec *MatchSpec) bool {
		attribute := block.GetAttribute(spec.Name)
		if attribute.IsNil() {
			return spec.IgnoreUndefined
		}
		return attribute.GreaterThan(spec.MatchValue)
	},
	GreaterThanOrEqualTo: func(block block.Block, spec *MatchSpec) bool {
		attribute := block.GetAttribute(spec.Name)
		if attribute.IsNil() {
			return spec.IgnoreUndefined
		}
		return attribute.GreaterThanOrEqualTo(spec.MatchValue)
	},
	RegexMatches: func(block block.Block, spec *MatchSpec) bool {
		attribute := block.GetAttribute(spec.Name)
		if attribute.IsNil() {
			return spec.IgnoreUndefined
		}
		return attribute.RegexMatches(spec.MatchValue)
	},
	IsAny: func(block block.Block, spec *MatchSpec) bool {
		attribute := block.GetAttribute(spec.Name)
		return attribute != nil && attribute.IsAny(unpackInterfaceToInterfaceSlice(spec.MatchValue)...)
	},
	IsNone: func(block block.Block, spec *MatchSpec) bool {
		attribute := block.GetAttribute(spec.Name)
		if attribute.IsNil() {
			return spec.IgnoreUndefined
		}
		return attribute.IsNone(unpackInterfaceToInterfaceSlice(spec.MatchValue)...)
	},
}

func processFoundChecks(checks ChecksFile) {
	for _, customCheck := range checks.Checks {
		func(customCheck Check) {
			debug.Log("Loading check: %s\n", customCheck.Code)
			scanner.RegisterCheckRule(rule.Rule{
				LegacyID:  customCheck.Code,
				Service:   "custom",
				ShortCode: customCheck.Code,
				Documentation: rule.RuleDocumentation{
					Summary:    customCheck.Description,
					Links:      customCheck.RelatedLinks,
					Impact:     customCheck.Impact,
					Resolution: customCheck.Resolution,
				},
				Provider:        provider.CustomProvider,
				RequiredTypes:   customCheck.RequiredTypes,
				RequiredLabels:  customCheck.RequiredLabels,
				RequiredSources: customCheck.RequiredSources,
				DefaultSeverity: severity.Medium,
				CheckFunc: func(set result.Set, rootBlock block.Block, module block.Module) {
					matchSpec := customCheck.MatchSpec
					if !evalMatchSpec(rootBlock, matchSpec, module) {
						set.AddResult().
							WithDescription("Custom check failed for resource %s. %s", rootBlock.FullName(), customCheck.ErrorMessage).
							WithSeverity(customCheck.Severity)
					}
				},
			})
		}(*customCheck)
	}
}

func evalMatchSpec(b block.Block, spec *MatchSpec, module block.Module) bool {
	if b.IsNil() {
		return false
	}
	var evalResult bool

	if spec.PreConditions != nil {
		for _, preCondition := range spec.PreConditions {
			if !evalMatchSpec(b, &preCondition, module) {
				// precondition not met
				return true
			}
		}
	}

	switch spec.Action {
	case InModule:
		return b.InModule()
	case RegexMatches:
		if !matchFunctions[RegexMatches](b, spec) {
			return spec.IgnoreUnmatched
		}
	case HasTag:
		return checkTags(b, spec, module)
	case OfType:
		return ofType(b, spec)
	case RequiresPresence:
		return resourceFound(spec, module)
	case Not:
		return notifyPredicate(b, spec, module)
	case And:
		return processAndPredicate(spec, b, module)
	case Or:
		return processOrPredicate(spec, b, module)
	default:
		evalResult = matchFunctions[spec.Action](b, spec)
	}

	if spec.SubMatch != nil {
		evalResult = processSubMatches(spec, b, evalResult)
	}

	return evalResult
}

func notifyPredicate(b block.Block, spec *MatchSpec, module block.Module) bool {
	return !evalMatchSpec(b, &spec.PredicateMatchSpec[0], module)
}

func processOrPredicate(spec *MatchSpec, b block.Block, module block.Module) bool {
	for _, childSpec := range spec.PredicateMatchSpec {
		if evalMatchSpec(b, &childSpec, module) {
			return true
		}
	}
	return false
}

func processAndPredicate(spec *MatchSpec, b block.Block, module block.Module) bool {
	set := make(map[bool]bool)

	for _, childSpec := range spec.PredicateMatchSpec {
		result := evalMatchSpec(b, &childSpec, module)
		set[result] = true

	}

	return len(set) == 1 && set[true] == true
}

func processSubMatches(spec *MatchSpec, b block.Block, evalResult bool) bool {
	for _, b := range b.GetBlocks(spec.Name) {
		evalResult = evalMatchSpec(b, spec.SubMatch, nil)
		if !evalResult {
			break
		}
	}

	return evalResult
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
