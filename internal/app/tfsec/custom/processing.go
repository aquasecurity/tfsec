package custom

import (
	"fmt"
	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

var matchFunctions = map[CheckAction]func(*parser.Block, *MatchSpec) bool{
	IsPresent: func(block *parser.Block, spec *MatchSpec) bool {
		return block.HasChild(spec.Name) || spec.IgnoreUndefined
},
	NotPresent: func(block *parser.Block, spec *MatchSpec) bool { return !block.HasChild(spec.Name) },
	IsEmpty: func(block *parser.Block, spec *MatchSpec) bool {
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
	StartsWith: func(block *parser.Block, spec *MatchSpec) bool {
		attribute := block.GetAttribute(spec.Name)
		if attribute == nil {
			return spec.IgnoreUndefined
		}
		return attribute.StartsWith(spec.MatchValue)
	},
	EndsWith: func(block *parser.Block, spec *MatchSpec) bool {
		attribute := block.GetAttribute(spec.Name)
		if attribute == nil {
			return spec.IgnoreUndefined
		}
		return attribute.EndsWith(spec.MatchValue)
	},
	Contains: func(block *parser.Block, spec *MatchSpec) bool {
		attribute := block.GetAttribute(spec.Name)
		if attribute == nil {
			return spec.IgnoreUndefined
		}
		return attribute.Contains(spec.MatchValue, parser.IgnoreCase)
	},
	NotContains: func(block *parser.Block, spec *MatchSpec) bool {
		attribute := block.GetAttribute(spec.Name)
		if attribute == nil {
			return spec.IgnoreUndefined
		}
		return !attribute.Contains(spec.MatchValue)
	},
	Equals: func(block *parser.Block, spec *MatchSpec) bool {
		attribute := block.GetAttribute(spec.Name)
		if attribute == nil {
			return spec.IgnoreUndefined
		}
		return attribute.Equals(spec.MatchValue)
	},
	LessThan: func(block *parser.Block, spec *MatchSpec) bool {
		attribute := block.GetAttribute(spec.Name)
		if attribute == nil {
			return spec.IgnoreUndefined
		}
		return attribute.LessThan(spec.MatchValue)
	},
	LessThanOrEqualTo: func(block *parser.Block, spec *MatchSpec) bool {
		attribute := block.GetAttribute(spec.Name)
		if attribute == nil {
			return spec.IgnoreUndefined
		}
		return attribute.LessThanOrEqualTo(spec.MatchValue)
	},
	GreaterThan: func(block *parser.Block, spec *MatchSpec) bool {
		attribute := block.GetAttribute(spec.Name)
		if attribute == nil {
			return spec.IgnoreUndefined
		}
		return attribute.GreaterThan(spec.MatchValue)
	},
	GreaterThanOrEqualTo: func(block *parser.Block, spec *MatchSpec) bool {
		attribute := block.GetAttribute(spec.Name)
		if attribute == nil {
			return spec.IgnoreUndefined
		}
		return attribute.GreaterThanOrEqualTo(spec.MatchValue)
	},
	RegexMatches: func(block *parser.Block, spec *MatchSpec) bool {
		attribute := block.GetAttribute(spec.Name)
		if attribute == nil {
			return spec.IgnoreUndefined
		}
		return attribute.RegexMatches(spec.MatchValue)
	},
	IsAny: func(block *parser.Block, spec *MatchSpec) bool {
		attribute := block.GetAttribute(spec.Name)
		return attribute != nil && attribute.IsAny(unpackInterfaceToInterfaceSlice(spec.MatchValue)...)
	},
	IsNone: func(block *parser.Block, spec *MatchSpec) bool {
		attribute := block.GetAttribute(spec.Name)
		if attribute == nil {
			return true
		}
		return attribute.IsNone(unpackInterfaceToInterfaceSlice(spec.MatchValue)...)
	},
}

func processFoundChecks(checks ChecksFile) {
	for _, customCheck := range checks.Checks {
		func(customCheck Check) {
			fmt.Printf("Loading check: %s\n", customCheck.Code)
			scanner.RegisterCheck(scanner.Check{
				Code: customCheck.Code,
				Documentation: scanner.CheckDocumentation{
					Summary: scanner.RuleSummary(customCheck.Code),
					Links:   customCheck.RelatedLinks,
				},
				Provider:       "custom",
				RequiredTypes:  customCheck.RequiredTypes,
				RequiredLabels: customCheck.RequiredLabels,
				CheckFunc: func(check *scanner.Check, rootBlock *parser.Block, ctx *scanner.Context) []scanner.Result {
					matchSpec := customCheck.MatchSpec
					if !evalMatchSpec(rootBlock, matchSpec, ctx) {
						return []scanner.Result{
							check.NewResult(
								fmt.Sprintf("Custom check failed for resource %s. %s", rootBlock.FullName(), customCheck.ErrorMessage),
								rootBlock.Range(),
								customCheck.Severity,
							),
						}
					}
					return nil
				},
			})
		}(*customCheck)
	}
}

func evalMatchSpec(block *parser.Block, spec *MatchSpec, ctx *scanner.Context) bool {
	if block == nil {
		return false
	}
	evalResult := false
	if spec.Action == InModule {
		return block.InModule()
	}
	if spec.Action == RegexMatches && !matchFunctions[RegexMatches](block, spec) {
		return false
	}

	if spec.Action == RequiresPresence {
		return resourceFound(spec, ctx)
	}

	if spec.Action == Not {
		return !evalMatchSpec(block, &spec.PredicateMatchSpec[0], ctx)
	}

	// This And MatchSpec is only true if all childSpecs return true
	if spec.Action == And {
		for _, childSpec := range spec.PredicateMatchSpec {
			if !evalMatchSpec(block, &childSpec, ctx) {
				return false
			}
		}
		return true
	}

	// If a single childSpec is true then this Or matchSpec is true
	if spec.Action == Or {
		for _, childSpec := range spec.PredicateMatchSpec {
			if evalMatchSpec(block, &childSpec, ctx) {
				return true
			}
		}
		return false
	}

	evalResult = matchFunctions[spec.Action](block, spec)

	if spec.SubMatch != nil {
		for _, block := range block.GetBlocks(spec.Name) {
			evalResult = evalMatchSpec(block, spec.SubMatch, nil)
			if !evalResult {
				break
			}
		}
	}

	return evalResult
}

func resourceFound(spec *MatchSpec, ctx *scanner.Context) bool {
	val := fmt.Sprintf("%v", spec.Name)
	byType := ctx.GetResourcesByType(val)
	return len(byType) > 0
}

func unpackInterfaceToInterfaceSlice(t interface{}) []interface{} {
	switch t := t.(type) {
	case []interface{}:
		var result []interface{}
		for _, i := range t {
			result = append(result, i)
		}
		return result
	}
	return nil
}
