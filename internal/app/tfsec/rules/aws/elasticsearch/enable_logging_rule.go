package elasticsearch

// generator-locked
import (
	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/severity"

	"github.com/aquasecurity/tfsec/pkg/provider"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID:  "AWS070",
		Service:   "elastic-search",
		ShortCode: "enable-logging",
		Documentation: rule.RuleDocumentation{
			Summary:    "AWS ES Domain should have logging enabled",
			Impact:     "Logging provides vital information about access and usage",
			Resolution: "Enable logging for ElasticSearch domains",
			Explanation: `
AWS ES domain should have logging enabled by default.
`,
			BadExample: []string{`
resource "aws_elasticsearch_domain" "example" {
  // other config

  // One of the log_publishing_options has to be AUDIT_LOGS
  log_publishing_options {
    cloudwatch_log_group_arn = aws_cloudwatch_log_group.example.arn
    log_type                 = "INDEX_SLOW_LOGS"
  }
}
`},
			GoodExample: []string{`
resource "aws_elasticsearch_domain" "example" {
  // other config

  // At minimum we should have AUDIT_LOGS enabled
  log_publishing_options {
    cloudwatch_log_group_arn = aws_cloudwatch_log_group.example.arn
    log_type                 = "AUDIT_LOGS"
  }
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/elasticsearch_domain#log_publishing_options",
			},
		},
		Provider:        provider.AWSProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_elasticsearch_domain"},
		DefaultSeverity: severity.Medium,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ block.Module) {

			logPublishingOptions := resourceBlock.GetBlocks("log_publishing_options")

			auditLogFound := false
			for _, logPublishingOption := range logPublishingOptions {
				logType := logPublishingOption.GetAttribute("log_type")
				if logType.IsNotNil() {
					if logType.Equals("AUDIT_LOGS") {
						auditLogFound = true
					}
				}
			}

			if !auditLogFound {
				set.AddResult().
					WithDescription("Resource '%s' is missing 'AUDIT_LOGS` in one of the `log_publishing_options`-`log_type` attributes so audit log is not enabled", resourceBlock.FullName())
			}
		},
	})
}
