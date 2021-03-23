package checks

import (
	"fmt"
	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
	"strings"
)

const AWSESDomainLoggingEnabled scanner.RuleCode = "AWS070"
const AWSESDomainLoggingEnabledDescription scanner.RuleSummary = "AWS ES Domain should have logging enabled"
const AWSESDomainLoggingEnabledExplanation = `
AWS ES domain should have logging enabled by default.
`
const AWSESDomainLoggingEnabledBadExample = `
resource "aws_elasticsearch_domain" "example" {
  // other config
  // no log_publishing_options
}
`
const AWSESDomainLoggingEnabledGoodExample = `
resource "aws_elasticsearch_domain" "example" {
  // other config

  log_publishing_options {
    cloudwatch_log_group_arn = aws_cloudwatch_log_group.example.arn
    log_type                 = "AUDIT_LOGS"
  }
}
`

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code: AWSESDomainLoggingEnabled,
		Documentation: scanner.CheckDocumentation{
			Summary:     AWSESDomainLoggingEnabledDescription,
			Explanation: AWSESDomainLoggingEnabledExplanation,
			BadExample:  AWSESDomainLoggingEnabledBadExample,
			GoodExample: AWSESDomainLoggingEnabledGoodExample,
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/elasticsearch_domain#log_publishing_options",
			},
		},
		Provider:       scanner.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_elasticsearch_domain"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {

			if block.MissingChild("log_publishing_options") {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' has no log_publishing_options block specified, no loging is enabled", block.FullName()),
						block.Range(),
						scanner.SeverityError,
					),
				}
			}

			logPublishingOptions := block.GetBlock("log_publishing_options")
			if logPublishingOptions.MissingChild("log_type") {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' is missing log_type configuration, no loging is enabled", block.FullName()),
						logPublishingOptions.Range(),
						scanner.SeverityError,
					),
				}
			}

			logType := logPublishingOptions.GetAttribute("log_type")
					if !strings.Contains(logType.Value().AsString(), "AUDIT_LOGS") {
						return []scanner.Result{
							check.NewResult(
								fmt.Sprintf("Resource '%s' is missing 'AUDIT_LOGS` in `log_type` so audit log is not enabled", block.FullName()),
								logPublishingOptions.Range(),
								scanner.SeverityError,
							),
						}
					}

			return nil
		},
	})
}
