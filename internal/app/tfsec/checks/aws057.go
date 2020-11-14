package checks

import (
	"fmt"
	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

const AWSElasticSearchHasDomainLogging scanner.RuleCode = "AWS057"
const AWSElasticSearchHasDomainLoggingDescription scanner.RuleSummary = "Domain logging should be enabled for Elastic Search domains"
const AWSElasticSearchHasDomainLoggingExplanation = `
Amazon ES exposes four Elasticsearch logs through Amazon CloudWatch Logs: error logs, search slow logs, index slow logs, and audit logs. 

Search slow logs, index slow logs, and error logs are useful for troubleshooting performance and stability issues. 

Audit logs track user activity for compliance purposes. 

All the logs are disabled by default. 

`
const AWSElasticSearchHasDomainLoggingBadExample = `
resource "aws_elasticsearch_domain" "bad_example" {
  domain_name           = "example"
  elasticsearch_version = "1.5"
}

resource "aws_elasticsearch_domain" "bad_example" {
  domain_name           = "example"
  elasticsearch_version = "1.5"

  log_publishing_options {
    cloudwatch_log_group_arn = aws_cloudwatch_log_group.example.arn
    log_type                 = "INDEX_SLOW_LOGS"
    enabled                  = false  
  }
}
`
const AWSElasticSearchHasDomainLoggingGoodExample = `
resource "aws_elasticsearch_domain" "good_example" {
  domain_name           = "example"
  elasticsearch_version = "1.5"

  log_publishing_options {
    cloudwatch_log_group_arn = aws_cloudwatch_log_group.example.arn
    log_type                 = "INDEX_SLOW_LOGS"
    enabled                  = true  
  }
}

resource "aws_elasticsearch_domain" "good_example" {
  domain_name           = "example"
  elasticsearch_version = "1.5"

  log_publishing_options {
    cloudwatch_log_group_arn = aws_cloudwatch_log_group.example.arn
    log_type                 = "INDEX_SLOW_LOGS"
    enabled                  = true  
  }
}
`

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code: AWSElasticSearchHasDomainLogging,
		Documentation: scanner.CheckDocumentation{
			Summary:     AWSElasticSearchHasDomainLoggingDescription,
			Explanation: AWSElasticSearchHasDomainLoggingExplanation,
			BadExample:  AWSElasticSearchHasDomainLoggingBadExample,
			GoodExample: AWSElasticSearchHasDomainLoggingGoodExample,
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/elasticsearch_domain#log_type",
				"https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-createdomain-configure-slow-logs.html",
			},
		},
		Provider:       scanner.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_elasticsearch_domain"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {

			if block.MissingChild("log_publishing_options") {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' does not configure logging at rest on the domain.", block.FullName()),
						block.Range(),
						scanner.SeverityError,
					),
				}
			}

			logOptions := block.GetBlock("log_publishing_options")
			enabled := logOptions.GetAttribute("enabled")

			if enabled != nil && enabled.IsFalse() {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' explicitly disables logging on the domain.", block.FullName()),
						block.Range(),
						scanner.SeverityError,
					),
				}
			}

			return nil
		},
	})
}
