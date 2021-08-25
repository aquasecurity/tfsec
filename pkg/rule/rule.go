package rule

import (
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/types"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

// Rule is a targeted security test which can be applied to terraform templates. It includes the types to run on e.g.
// "resource", and the labels to run on e.g. "aws_s3_bucket".
type Rule struct {
	DefSecCheck rules.RuleDef
	LegacyID    string

	// BadExample (hcl) contains Terraform code which would cause the check to fail
	BadExample []string

	// GoodExample (hcl) modifies the BadExample content to cause the check to pass
	GoodExample []string

	// Links are URLs which contain further reading related to the check
	Links []string

	RequiredTypes   []string
	RequiredLabels  []string
	RequiredSources []string
	CheckTerraform  func(block.Block, block.Module) types.Results
}

func (r Rule) ID() string {
	return r.DefSecCheck.ID()
}
