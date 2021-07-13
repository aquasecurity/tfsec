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

const AWSElasticSearchHasDomainLogging = "AWS057"
const AWSElasticSearchHasDomainLoggingDescription = "Domain logging should be enabled for Elastic Search domains"
const AWSElasticSearchHasDomainLoggingImpact = "Logging provides vital information about access and usage"
const AWSElasticSearchHasDomainLoggingResolution = "Enable logging for ElasticSearch domains"
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
	scanner.RegisterCheckRule(rule.Rule{
		ID: AWSElasticSearchHasDomainLogging,
		Documentation: rule.RuleDocumentation{
			Summary:     AWSElasticSearchHasDomainLoggingDescription,
			Impact:      AWSElasticSearchHasDomainLoggingImpact,
			Resolution:  AWSElasticSearchHasDomainLoggingResolution,
			Explanation: AWSElasticSearchHasDomainLoggingExplanation,
			BadExample:  AWSElasticSearchHasDomainLoggingBadExample,
			GoodExample: AWSElasticSearchHasDomainLoggingGoodExample,
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/elasticsearch_domain#log_type",
				"https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-createdomain-configure-slow-logs.html",
			},
		},
		Provider:        provider.AWSProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_elasticsearch_domain"},
		DefaultSeverity: severity.Medium,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ *hclcontext.Context) {

			if resourceBlock.MissingChild("log_publishing_options") {
				set.Add(
					result.New(resourceBlock).
						WithDescription(fmt.Sprintf("Resource '%s' does not configure logging at rest on the domain.", resourceBlock.FullName())).
						WithRange(resourceBlock.Range()),
				)
				return
			}

			logOptions := resourceBlock.GetBlocks("log_publishing_options")
			for _, logOption := range logOptions {
				enabledAttr := logOption.GetAttribute("enabled")
				if enabledAttr != nil && enabledAttr.IsFalse() {
					set.Add(
						result.New(resourceBlock).
							WithDescription(fmt.Sprintf("Resource '%s' explicitly disables logging on the domain.", resourceBlock.FullName())).
							WithRange(enabledAttr.Range()).
							WithAttributeAnnotation(enabledAttr),
					)
					return
				}
			}

		},
	})
}
