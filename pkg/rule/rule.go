package rule

import (
	"github.com/aquasecurity/tfsec/pkg/provider"
	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/severity"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/hclcontext"
)

// Rule is a targeted security test which can be applied to terraform templates. It includes the types to run on e.g.
// "resource", and the labels to run on e.g. "aws_s3_bucket".
type Rule struct {
	ID              string
	Documentation   RuleDocumentation
	Provider        provider.Provider
	RequiredTypes   []string
	RequiredLabels  []string
	DefaultSeverity severity.Severity
	CheckFunc       func(result.Set, block.Block, *hclcontext.Context)
}

type RuleDocumentation struct {

	// Summary is a brief description of the check, e.g. "Unencrypted S3 Bucket"
	Summary string

	// Explanation (markdown) contains reasoning for the check, details on it's value, and remediation info
	Explanation string

	// Impact contains a brief summary of the impact of failing the check
	Impact string

	// Resolution contains a brief summary of the resolution for the failing check
	Resolution string

	// BadExample (hcl) contains Terraform code which would cause the check to fail
	BadExample string

	// GoodExample (hcl) modifies the BadExample content to cause the check to pass
	GoodExample string

	// Links are URLs which contain further reading related to the check
	Links []string
}
