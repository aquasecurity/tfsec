package elasticsearch

import (
	"github.com/aquasecurity/defsec/rules/aws/elasticsearch"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID: "AWS057",
		BadExample: []string{`
 resource "aws_elasticsearch_domain" "bad_example" {
   domain_name           = "example"
   elasticsearch_version = "1.5"
 }
 `, `
 resource "aws_elasticsearch_domain" "bad_example" {
   domain_name           = "example"
   elasticsearch_version = "1.5"
 
   log_publishing_options {
     cloudwatch_log_group_arn = aws_cloudwatch_log_group.example.arn
     log_type                 = "AUDIT_LOGS"
     enabled                  = false  
   }
 }
 `},
		GoodExample: []string{`
 resource "aws_elasticsearch_domain" "good_example" {
   domain_name           = "example"
   elasticsearch_version = "1.5"
 
   log_publishing_options {
     cloudwatch_log_group_arn = aws_cloudwatch_log_group.example.arn
     log_type                 = "AUDIT_LOGS"
     enabled                  = true  
   }
 }
 `},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/elasticsearch_domain#log_type",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_elasticsearch_domain"},
		Base:           elasticsearch.CheckEnableDomainLogging,
	})
}
