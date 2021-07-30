package requirements

import (
	"fmt"
)

type custom struct {
	blockType   string
	blockLabel  string
	exampleCode string
}

func Custom(blockType string, blockLabel string, exampleCode string) Requirement {
	var req custom
	req.blockType = blockType
	req.blockLabel = blockLabel
	req.exampleCode = exampleCode
	return &req
}

func (a *custom) GenerateGoodExample() string {
	if a.exampleCode != "" {
		return a.exampleCode
	}
	return fmt.Sprintf(`
%s "%s" "%s" {

}
`, a.blockType, a.blockLabel, "good_example")
}

func (a *custom) GenerateBadExample() string {
	if a.exampleCode != "" {
		return a.exampleCode
	}
	return fmt.Sprintf(`
%s "%s" "%s" {

}
`, a.blockType, a.blockLabel, "bad_example")
}

func (a *custom) GenerateRuleCode() string {
	return " // TODO: code goes here"
}

func (a *custom) RequirementType() RequirementType {
	return CustomRequirement
}
