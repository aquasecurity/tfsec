package rule

import (
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

// Rule is a targeted security test which can be applied to terraform templates. It includes the types to run on e.g.
// "resource", and the labels to run on e.g. "aws_s3_bucket".
type Rule struct {
	Base            rules.RegisteredRule
	RequiredTypes   []string
	RequiredLabels  []string
	RequiredSources []string
	CheckTerraform  func(block.Block, block.Module) rules.Results
}

func (r Rule) ID() string {
	return r.Base.Rule().LongID()
}
