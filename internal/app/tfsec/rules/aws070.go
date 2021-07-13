package rules

import (
	"fmt"

	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/severity"

	"github.com/aquasecurity/tfsec/pkg/provider"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/hclcontext"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

const AWSESDomainLoggingEnabled = "AWS070"
const AWSESDomainLoggingEnabledDescription = "AWS ES Domain should have logging enabled"
const AWSESDomainLoggingEnabledImpact = "Logging provides vital information about access and usage"
const AWSESDomainLoggingEnabledResolution = "Enable logging for ElasticSearch domains"
const AWSESDomainLoggingEnabledExplanation = `
AWS ES domain should have logging enabled by default.
`
const AWSESDomainLoggingEnabledBadExample = `
resource "aws_elasticsearch_domain" "example" {
  // other config

  // One of the log_publishing_options has to be AUDIT_LOGS
  log_publishing_options {
    cloudwatch_log_group_arn = aws_cloudwatch_log_group.example.arn
    log_type                 = "INDEX_SLOW_LOGS"
  }
}
`
const AWSESDomainLoggingEnabledGoodExample = `
resource "aws_elasticsearch_domain" "example" {
  // other config

  // At minimum we should have AUDIT_LOGS enabled
  log_publishing_options {
    cloudwatch_log_group_arn = aws_cloudwatch_log_group.example.arn
    log_type                 = "AUDIT_LOGS"
  }
}
`

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		ID: AWSESDomainLoggingEnabled,
		Documentation: rule.RuleDocumentation{
			Summary:     AWSESDomainLoggingEnabledDescription,
			Impact:      AWSESDomainLoggingEnabledImpact,
			Resolution:  AWSESDomainLoggingEnabledResolution,
			Explanation: AWSESDomainLoggingEnabledExplanation,
			BadExample:  AWSESDomainLoggingEnabledBadExample,
			GoodExample: AWSESDomainLoggingEnabledGoodExample,
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/elasticsearch_domain#log_publishing_options",
			},
		},
		Provider:        provider.AWSProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_elasticsearch_domain"},
		DefaultSeverity: severity.Medium,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ *hclcontext.Context) {
			logPublishingOptions := resourceBlock.GetBlocks("log_publishing_options")
			if len(logPublishingOptions) > 0 {
				auditLogFound := false
				for _, logPublishingOption := range logPublishingOptions {
					logType := logPublishingOption.GetAttribute("log_type")
					if logType != nil {
						if logType.Equals("AUDIT_LOGS") {
							auditLogFound = true
						}
					}
				}

				if !auditLogFound {
					set.Add(
						result.New(resourceBlock).
							WithDescription(fmt.Sprintf("Resource '%s' is missing 'AUDIT_LOGS` in one of the `log_publishing_options`-`log_type` attributes so audit log is not enabled", resourceBlock.FullName())).
							WithRange(resourceBlock.Range()),
					)
				}
			}

		},
	})
}
