package custom

import (
	"fmt"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

var matchFunctions = map[CheckAction]func(*parser.Block, *MatchSpec) bool{
	IsPresent:  func(block *parser.Block, spec *MatchSpec) bool { return block.HasChild(spec.Name) },
	NotPresent: func(block *parser.Block, spec *MatchSpec) bool { return !block.HasChild(spec.Name) },
	StartsWith: func(block *parser.Block, spec *MatchSpec) bool {
		attribute := block.GetAttribute(spec.Name)
		return attribute != nil && attribute.StartsWith(spec.MatchValue)
	},
	EndsWith: func(block *parser.Block, spec *MatchSpec) bool {
		attribute := block.GetAttribute(spec.Name)
		return attribute != nil && attribute.EndsWith(spec.MatchValue)
	},
	Contains: func(block *parser.Block, spec *MatchSpec) bool {
		attribute := block.GetAttribute(spec.Name)
		return attribute != nil && attribute.Contains(spec.MatchValue)
	},
	Equals: func(block *parser.Block, spec *MatchSpec) bool {
		attribute := block.GetAttribute(spec.Name)
		return attribute != nil && attribute.Equals(spec.MatchValue)
	},
	RegexMatches: func(block *parser.Block, spec *MatchSpec) bool {
		attribute := block.GetAttribute(spec.Name)
		return attribute != nil && attribute.RegexMatches(spec.MatchValue)
	},
	IsAny: func(block *parser.Block, spec *MatchSpec) bool {
		attribute := block.GetAttribute(spec.Name)
		return attribute != nil && attribute.IsAny(unpackInterfaceToInterfaceSlice(spec.MatchValue)...)
	},
	IsNone: func(block *parser.Block, spec *MatchSpec) bool {
		attribute := block.GetAttribute(spec.Name)
		if attribute == nil {
			// attribute is null so can't match
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
				CheckFunc: func(check *scanner.Check, rootBlock *parser.Block, _ *scanner.Context) []scanner.Result {
					matchSpec := customCheck.MatchSpec
					if !evalMatchSpec(rootBlock, matchSpec) {
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

func evalMatchSpec(block *parser.Block, spec *MatchSpec) bool {
	if block == nil {
		return false
	}
	evalResult := false
	if spec.Action == InModule {
		return block.InModule()
	}
	if spec.Action == RegexMatches && !matchFunctions[RegexMatches](block, spec) {
		return true
	}
	evalResult = matchFunctions[spec.Action](block, spec)

	if spec.SubMatch != nil {
		if block.HasBlock(spec.Name) {
			block = block.GetBlock(spec.Name)
		}
		evalResult = evalMatchSpec(block, spec.SubMatch)
	}
	return evalResult
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
