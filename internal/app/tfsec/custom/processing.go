package custom

import (
	"fmt"
	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

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
								fmt.Sprintf("Custom check failed for resource %s. %s", rootBlock.Name(), customCheck.ErrorMessage),
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
	attribute := block.GetAttribute(spec.Name)
	switch spec.Action {
	case InModule:
		return block.InModule()
	case IsPresent:
		evalResult = block.HasChild(spec.Name)
		break
	case NotPresent:
		evalResult = !block.HasChild(spec.Name)
		break
	case StartsWith:
		evalResult = attribute != nil && attribute.StartsWith(spec.MatchValue)
		break
	case EndsWith:
		evalResult = attribute != nil && attribute.EndsWith(spec.MatchValue)
		break
	case Contains:
		evalResult = attribute != nil && attribute.Contains(spec.MatchValue)
		break
	case Equals:
		evalResult = attribute != nil && attribute.Equals(spec.MatchValue)
		break
	}

	if spec.SubMatch != nil {
		subBlock := block.GetBlock(spec.Name)
		evalResult = evalMatchSpec(subBlock, spec.SubMatch)
	}

	return evalResult
}
