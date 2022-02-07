package custom

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/gocty"

	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/tfsec/internal/pkg/block"
	"github.com/aquasecurity/tfsec/internal/pkg/debug"
	"github.com/aquasecurity/tfsec/internal/pkg/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

var matchFunctions = map[CheckAction]func(*block.Block, *MatchSpec, *customContext) bool{
	IsPresent: func(b *block.Block, spec *MatchSpec, customCtx *customContext) bool {
		return b.HasChild(spec.Name) || spec.IgnoreUndefined
	},
	NotPresent: func(b *block.Block, spec *MatchSpec, customCtx *customContext) bool {
		return !b.HasChild(spec.Name)
	},
	IsEmpty: func(b *block.Block, spec *MatchSpec, customCtx *customContext) bool {
		if b.MissingChild(spec.Name) {
			return true
		}

		attribute := b.GetAttribute(spec.Name)
		if attribute != nil {
			return attribute.IsEmpty()
		}
		childBlock := b.GetBlock(spec.Name)
		return childBlock.IsEmpty()
	},
	StartsWith: func(b *block.Block, spec *MatchSpec, customCtx *customContext) bool {
		attribute := b.GetAttribute(spec.Name)
		if attribute.IsNil() {
			return spec.IgnoreUndefined
		}
		return attribute.StartsWith(processMatchValueVariables(spec.MatchValue, customCtx.variables))
	},
	EndsWith: func(b *block.Block, spec *MatchSpec, customCtx *customContext) bool {
		attribute := b.GetAttribute(spec.Name)
		if attribute.IsNil() {
			return spec.IgnoreUndefined
		}
		return attribute.EndsWith(processMatchValueVariables(spec.MatchValue, customCtx.variables))
	},
	Contains: func(b *block.Block, spec *MatchSpec, customCtx *customContext) bool {
		attribute := b.GetAttribute(spec.Name)
		if attribute.IsNil() {
			return spec.IgnoreUndefined
		}
		return attribute.Contains(processMatchValueVariables(spec.MatchValue, customCtx.variables), block.IgnoreCase)
	},
	NotContains: func(b *block.Block, spec *MatchSpec, customCtx *customContext) bool {
		attribute := b.GetAttribute(spec.Name)
		if attribute.IsNil() {
			return spec.IgnoreUndefined
		}
		return !attribute.Contains(processMatchValueVariables(spec.MatchValue, customCtx.variables))
	},
	Equals: func(b *block.Block, spec *MatchSpec, customCtx *customContext) bool {
		attribute := b.GetAttribute(spec.Name)
		if attribute.IsNil() {
			return spec.IgnoreUndefined
		}
		return attribute.Equals(processMatchValueVariables(spec.MatchValue, customCtx.variables))
	},
	NotEqual: func(b *block.Block, spec *MatchSpec, customCtx *customContext) bool {
		attribute := b.GetAttribute(spec.Name)
		if attribute.IsNil() {
			return spec.IgnoreUndefined
		}
		return attribute.NotEqual(processMatchValueVariables(spec.MatchValue, customCtx.variables))
	},
	LessThan: func(b *block.Block, spec *MatchSpec, customCtx *customContext) bool {
		attribute := b.GetAttribute(spec.Name)
		if attribute.IsNil() {
			return spec.IgnoreUndefined
		}
		return attribute.LessThan(spec.MatchValue)
	},
	LessThanOrEqualTo: func(b *block.Block, spec *MatchSpec, customCtx *customContext) bool {
		attribute := b.GetAttribute(spec.Name)
		if attribute.IsNil() {
			return spec.IgnoreUndefined
		}
		return attribute.LessThanOrEqualTo(spec.MatchValue)
	},
	GreaterThan: func(b *block.Block, spec *MatchSpec, customCtx *customContext) bool {
		attribute := b.GetAttribute(spec.Name)
		if attribute.IsNil() {
			return spec.IgnoreUndefined
		}
		return attribute.GreaterThan(spec.MatchValue)
	},
	GreaterThanOrEqualTo: func(b *block.Block, spec *MatchSpec, customCtx *customContext) bool {
		attribute := b.GetAttribute(spec.Name)
		if attribute.IsNil() {
			return spec.IgnoreUndefined
		}
		return attribute.GreaterThanOrEqualTo(spec.MatchValue)
	},
	RegexMatches: func(b *block.Block, spec *MatchSpec, customCtx *customContext) bool {
		attribute := b.GetAttribute(spec.Name)
		if attribute.IsNil() {
			return spec.IgnoreUndefined
		}
		return attribute.RegexMatches(processMatchValueVariables(spec.MatchValue, customCtx.variables))
	},
	RequiresPresence: func(b *block.Block, spec *MatchSpec, customCtx *customContext) bool {
		return resourceFound(spec, customCtx.module)
	},
	IsAny: func(b *block.Block, spec *MatchSpec, customCtx *customContext) bool {
		attribute := b.GetAttribute(spec.Name)
		return attribute != nil && attribute.IsAny(unpackInterfaceToInterfaceSlice(processMatchValueVariables(spec.MatchValue, customCtx.variables))...)
	},
	IsNone: func(b *block.Block, spec *MatchSpec, customCtx *customContext) bool {
		attribute := b.GetAttribute(spec.Name)
		if attribute.IsNil() {
			return spec.IgnoreUndefined
		}
		return attribute.IsNone(unpackInterfaceToInterfaceSlice(processMatchValueVariables(spec.MatchValue, customCtx.variables))...)
	},
}

var AttrMatchFunctions = map[CheckAction]func(*block.Attribute, *MatchSpec, *customContext) bool{
	IsPresent: func(a *block.Attribute, spec *MatchSpec, customCtx *customContext) bool {
		return a.Contains(spec.Name) || spec.IgnoreUndefined
	},
	NotPresent: func(a *block.Attribute, spec *MatchSpec, customCtx *customContext) bool {
		return !a.Contains(spec.Name)
	},
	StartsWith: func(a *block.Attribute, spec *MatchSpec, customCtx *customContext) bool {
		if attributeValue := a.MapValue(spec.Name); attributeValue.IsNull() {
			if !attributeValue.Type().Equals(cty.String) {
				return false
			}
			return strings.HasPrefix(attributeValue.AsString(), fmt.Sprintf("%v", processMatchValueVariables(spec.MatchValue, customCtx.variables)))
		}
		return spec.IgnoreUndefined
	},
	EndsWith: func(a *block.Attribute, spec *MatchSpec, customCtx *customContext) bool {
		if attributeValue := a.MapValue(spec.Name); !attributeValue.IsNull() {
			if !attributeValue.Type().Equals(cty.String) {
				return false
			}
			return strings.HasSuffix(attributeValue.AsString(), fmt.Sprintf("%v", processMatchValueVariables(spec.MatchValue, customCtx.variables)))
		}
		return spec.IgnoreUndefined
	},
	Equals: func(a *block.Attribute, spec *MatchSpec, customCtx *customContext) bool {
		if attributeValue := a.MapValue(spec.Name); !attributeValue.IsNull() {
			if !attributeValue.Type().Equals(cty.String) {
				return false
			}
			return attributeValue.AsString() == processMatchValueVariables(spec.MatchValue, customCtx.variables)
		}
		return spec.IgnoreUndefined
	},
	NotEqual: func(a *block.Attribute, spec *MatchSpec, customCtx *customContext) bool {
		if attributeValue := a.MapValue(spec.Name); !attributeValue.IsNull() {
			if !attributeValue.Type().Equals(cty.String) {
				return false
			}
			return attributeValue.AsString() != processMatchValueVariables(spec.MatchValue, customCtx.variables)
		}
		return spec.IgnoreUndefined
	},
	LessThan: func(a *block.Attribute, spec *MatchSpec, customCtx *customContext) bool {
		if attributeValue := a.MapValue(spec.Name); !attributeValue.IsNull() {
			if !attributeValue.Type().Equals(cty.Number) {
				return false
			}
			if matchValue, err := gocty.ToCtyValue(spec.MatchValue, cty.Number); err != nil {
				return false
			} else {
				return attributeValue.LessThan(matchValue).True()
			}
		}
		return spec.IgnoreUndefined
	},
	LessThanOrEqualTo: func(a *block.Attribute, spec *MatchSpec, customCtx *customContext) bool {
		if attributeValue := a.MapValue(spec.Name); !attributeValue.IsNull() {
			if !attributeValue.Type().Equals(cty.Number) {
				return false
			}
			if matchValue, err := gocty.ToCtyValue(spec.MatchValue, cty.Number); err != nil {
				return false
			} else {
				return attributeValue.LessThanOrEqualTo(matchValue).True()
			}
		}
		return spec.IgnoreUndefined
	},
	GreaterThan: func(a *block.Attribute, spec *MatchSpec, customCtx *customContext) bool {
		if attributeValue := a.MapValue(spec.Name); !attributeValue.IsNull() {
			if !attributeValue.Type().Equals(cty.Number) {
				return false
			}
			if matchValue, err := gocty.ToCtyValue(spec.MatchValue, cty.Number); err != nil {
				return false
			} else {
				return attributeValue.GreaterThan(matchValue).True()
			}
		}
		return spec.IgnoreUndefined
	},
	GreaterThanOrEqualTo: func(a *block.Attribute, spec *MatchSpec, customCtx *customContext) bool {
		if attributeValue := a.MapValue(spec.Name); !attributeValue.IsNull() {
			if !attributeValue.Type().Equals(cty.Number) {
				return false
			}
			if matchValue, err := gocty.ToCtyValue(spec.MatchValue, cty.Number); err != nil {
				return false
			} else {
				return attributeValue.GreaterThanOrEqualTo(matchValue).True()
			}
		}
		return spec.IgnoreUndefined
	},
}

func ProcessFoundChecks(checks ChecksFile) {
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
				CheckTerraform: func(rootBlock *block.Block, module *block.Module) (results rules.Results) {
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

func evalMatchSpec(b *block.Block, spec *MatchSpec, customCtx *customContext) bool {
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

	var matchFunctionsDirect = map[CheckAction]func(*block.Block, *MatchSpec, *customContext) bool{
		InModule: func(b *block.Block, spec *MatchSpec, customCtx *customContext) bool {
			return b.InModule()
		},
		HasTag: checkTags,
		OfType: func(b *block.Block, spec *MatchSpec, customCtx *customContext) bool {
			return ofType(b, spec)
		},
		Not: notifyPredicate,
		And: processAndPredicate,
		Or:  processOrPredicate,
	}

	if matchFunction, ok := matchFunctionsDirect[spec.Action]; ok {
		return matchFunction(b, spec, customCtx)
	} else {
		evalResult = matchFunctions[spec.Action](b, spec, customCtx)
	}

	if len(spec.AssignVariable) > 0 {
		customCtx.variables[spec.AssignVariable] = b.GetAttribute(spec.Name).AsStringValueOrDefault("", b).Value()
	}

	if spec.SubMatch != nil && evalResult {
		evalResult = processSubMatches(b, spec, customCtx)
	}

	if spec.SubMatchOne != nil && evalResult {
		evalResult = processSubMatchOnes(b, spec, customCtx)
	}

	return evalResult
}

func evalMatchSpecAttr(a *block.Attribute, spec *MatchSpec, customCtx *customContext) bool {
	for _, preCondition := range spec.PreConditions {
		clone := preCondition
		if !evalMatchSpecAttr(a, &clone, customCtx) {
			// precondition not met
			return true
		}
	}

	switch spec.Action {
	case Not:
		return notifyPredicateAttr(a, spec, customCtx)
	case And:
		return processAndPredicateAttr(a, spec, customCtx)
	case Or:
		return processOrPredicateAttr(a, spec, customCtx)
	default:
		if matchFunction, ok := AttrMatchFunctions[spec.Action]; ok {
			return matchFunction(a, spec, customCtx)
		} else {
			return false
		}
	}
}

func notifyPredicate(b *block.Block, spec *MatchSpec, customCtx *customContext) bool {
	return !evalMatchSpec(b, &spec.PredicateMatchSpec[0], customCtx)
}

func notifyPredicateAttr(a *block.Attribute, spec *MatchSpec, customCtx *customContext) bool {
	return !evalMatchSpecAttr(a, &spec.PredicateMatchSpec[0], customCtx)
}

func processOrPredicate(b *block.Block, spec *MatchSpec, customCtx *customContext) bool {
	for _, childSpec := range spec.PredicateMatchSpec {
		clone := childSpec
		if evalMatchSpec(b, &clone, customCtx) {
			return true
		}
	}
	return false
}

func processOrPredicateAttr(a *block.Attribute, spec *MatchSpec, customCtx *customContext) bool {
	for _, childSpec := range spec.PredicateMatchSpec {
		clone := childSpec
		if evalMatchSpecAttr(a, &clone, customCtx) {
			return true
		}
	}
	return false
}

func processAndPredicate(b *block.Block, spec *MatchSpec, customCtx *customContext) bool {
	set := make(map[bool]bool)

	for _, childSpec := range spec.PredicateMatchSpec {
		clone := childSpec
		result := evalMatchSpec(b, &clone, customCtx)
		set[result] = true
	}

	return len(set) == 1 && set[true]
}

func processAndPredicateAttr(a *block.Attribute, spec *MatchSpec, customCtx *customContext) bool {
	set := make(map[bool]bool)

	for _, childSpec := range spec.PredicateMatchSpec {
		clone := childSpec
		result := evalMatchSpecAttr(a, &clone, customCtx)
		set[result] = true
	}

	return len(set) == 1 && set[true]
}

func processSubMatches(b *block.Block, spec *MatchSpec, customCtx *customContext) bool {
	var subMatchTargetBlocks block.Blocks
	switch spec.Action {
	case RequiresPresence:
		subMatchTargetBlocks = customCtx.module.GetResourcesByType(spec.Name)
	default:
		subMatchTargetBlocks = b.GetBlocks(spec.Name)
		if targetAttribute := b.GetAttribute(spec.Name); targetAttribute.IsNotNil() {
			if !evalMatchSpecAttr(targetAttribute, spec.SubMatch, customCtx) {
				return false
			}
		}
	}
	for _, b := range subMatchTargetBlocks {
		if !evalMatchSpec(b, spec.SubMatch, customCtx) {
			return false
		}
	}

	return true
}

func processSubMatchOnes(b *block.Block, spec *MatchSpec, customCtx *customContext) bool {
	var subMatchTargetBlocks block.Blocks
	switch spec.Action {
	case RequiresPresence:
		subMatchTargetBlocks = customCtx.module.GetResourcesByType(spec.Name)
	default:
		subMatchTargetBlocks = b.GetBlocks(spec.Name)
	}
	matchFound := false
	for _, b := range subMatchTargetBlocks {
		if evalMatchSpec(b, spec.SubMatchOne, customCtx) {
			if matchFound {
				return false // found more than one matches
			} else {
				matchFound = true
			}
		}
	}
	return matchFound
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

func resourceFound(spec *MatchSpec, module *block.Module) bool {
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
