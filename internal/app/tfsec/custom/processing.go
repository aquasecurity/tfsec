package custom

import (
	"fmt"

	"github.com/tfsec/tfsec/pkg/provider"
	"github.com/tfsec/tfsec/pkg/severity"

	"github.com/tfsec/tfsec/pkg/result"

	"github.com/tfsec/tfsec/internal/app/tfsec/hclcontext"

	"github.com/tfsec/tfsec/internal/app/tfsec/block"

	"github.com/tfsec/tfsec/pkg/rule"

	"github.com/tfsec/tfsec/internal/app/tfsec/debug"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

var matchFunctions = map[CheckAction]func(*block.Block, *MatchSpec) bool{
	IsPresent: func(block *block.Block, spec *MatchSpec) bool {
		return block.HasChild(spec.Name) || spec.IgnoreUndefined
	},
	NotPresent: func(block *block.Block, spec *MatchSpec) bool { return !block.HasChild(spec.Name) },
	IsEmpty: func(block *block.Block, spec *MatchSpec) bool {
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
	StartsWith: func(block *block.Block, spec *MatchSpec) bool {
		attribute := block.GetAttribute(spec.Name)
		if attribute == nil {
			return spec.IgnoreUndefined
		}
		return attribute.StartsWith(spec.MatchValue)
	},
	EndsWith: func(block *block.Block, spec *MatchSpec) bool {
		attribute := block.GetAttribute(spec.Name)
		if attribute == nil {
			return spec.IgnoreUndefined
		}
		return attribute.EndsWith(spec.MatchValue)
	},
	Contains: func(b *block.Block, spec *MatchSpec) bool {
		attribute := b.GetAttribute(spec.Name)
		if attribute == nil {
			return spec.IgnoreUndefined
		}
		return attribute.Contains(spec.MatchValue, block.IgnoreCase)
	},
	NotContains: func(block *block.Block, spec *MatchSpec) bool {
		attribute := block.GetAttribute(spec.Name)
		if attribute == nil {
			return spec.IgnoreUndefined
		}
		return !attribute.Contains(spec.MatchValue)
	},
	Equals: func(block *block.Block, spec *MatchSpec) bool {
		attribute := block.GetAttribute(spec.Name)
		if attribute == nil {
			return spec.IgnoreUndefined
		}
		return attribute.Equals(spec.MatchValue)
	},
	LessThan: func(block *block.Block, spec *MatchSpec) bool {
		attribute := block.GetAttribute(spec.Name)
		if attribute == nil {
			return spec.IgnoreUndefined
		}
		return attribute.LessThan(spec.MatchValue)
	},
	LessThanOrEqualTo: func(block *block.Block, spec *MatchSpec) bool {
		attribute := block.GetAttribute(spec.Name)
		if attribute == nil {
			return spec.IgnoreUndefined
		}
		return attribute.LessThanOrEqualTo(spec.MatchValue)
	},
	GreaterThan: func(block *block.Block, spec *MatchSpec) bool {
		attribute := block.GetAttribute(spec.Name)
		if attribute == nil {
			return spec.IgnoreUndefined
		}
		return attribute.GreaterThan(spec.MatchValue)
	},
	GreaterThanOrEqualTo: func(block *block.Block, spec *MatchSpec) bool {
		attribute := block.GetAttribute(spec.Name)
		if attribute == nil {
			return spec.IgnoreUndefined
		}
		return attribute.GreaterThanOrEqualTo(spec.MatchValue)
	},
	RegexMatches: func(block *block.Block, spec *MatchSpec) bool {
		attribute := block.GetAttribute(spec.Name)
		if attribute == nil {
			return spec.IgnoreUndefined
		}
		return attribute.RegexMatches(spec.MatchValue)
	},
	IsAny: func(block *block.Block, spec *MatchSpec) bool {
		attribute := block.GetAttribute(spec.Name)
		return attribute != nil && attribute.IsAny(unpackInterfaceToInterfaceSlice(spec.MatchValue)...)
	},
	IsNone: func(block *block.Block, spec *MatchSpec) bool {
		attribute := block.GetAttribute(spec.Name)
		if attribute == nil {
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
				ID: customCheck.Code,
				Documentation: rule.RuleDocumentation{
					Summary:    customCheck.Description,
					Links:      customCheck.RelatedLinks,
					Impact:     customCheck.Impact,
					Resolution: customCheck.Resolution,
				},
				Provider:        provider.CustomProvider,
				RequiredTypes:   customCheck.RequiredTypes,
				RequiredLabels:  customCheck.RequiredLabels,
				DefaultSeverity: severity.Warning,
				CheckFunc: func(set result.Set, rootBlock *block.Block, ctx *hclcontext.Context) {
					matchSpec := customCheck.MatchSpec
					if !evalMatchSpec(rootBlock, matchSpec, ctx) {
						set.Add(
							result.New(rootBlock).
								WithDescription(fmt.Sprintf("Custom check failed for resource %s. %s", rootBlock.FullName(), customCheck.ErrorMessage)).
								WithRange(rootBlock.Range()).
								WithSeverity(customCheck.Severity),
						)
					}
				},
			})
		}(*customCheck)
	}
}

func evalMatchSpec(b *block.Block, spec *MatchSpec, ctx *hclcontext.Context) bool {
	if b == nil {
		return false
	}
	evalResult := false
	if spec.Action == InModule {
		return b.InModule()
	}
	if spec.Action == RegexMatches && !matchFunctions[RegexMatches](b, spec) {
		return spec.IgnoreUnmatched
	}

	if spec.Action == HasTag {
		return checkTags(b, spec, ctx)
	}

	if spec.Action == OfType {
		return ofType(b, spec)
	}

	if spec.Action == RequiresPresence {
		return resourceFound(spec, ctx)
	}

	if spec.Action == Not {
		return !evalMatchSpec(b, &spec.PredicateMatchSpec[0], ctx)
	}

	// This And MatchSpec is only true if all childSpecs return true
	if spec.Action == And {
		for _, childSpec := range spec.PredicateMatchSpec {
			if !evalMatchSpec(b, &childSpec, ctx) {
				return false
			}
		}
		return true
	}

	// If a single childSpec is true then this Or matchSpec is true
	if spec.Action == Or {
		for _, childSpec := range spec.PredicateMatchSpec {
			if evalMatchSpec(b, &childSpec, ctx) {
				return true
			}
		}
		return false
	}

	evalResult = matchFunctions[spec.Action](b, spec)

	if spec.SubMatch != nil {
		for _, b := range b.GetBlocks(spec.Name) {
			evalResult = evalMatchSpec(b, spec.SubMatch, nil)
			if !evalResult {
				break
			}
		}
	}

	return evalResult
}

func resourceFound(spec *MatchSpec, ctx *hclcontext.Context) bool {
	val := fmt.Sprintf("%v", spec.Name)
	byType := ctx.GetResourcesByType(val)
	return len(byType) > 0
}

func unpackInterfaceToInterfaceSlice(t interface{}) []interface{} {
	switch t := t.(type) {
	case []interface{}:
		return t
	}
	return nil
}
