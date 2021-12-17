package elasticsearch

import (
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/rules/aws/elasticsearch"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
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
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {

			if resourceBlock.MissingChild("log_publishing_options") {
				results.Add("Resource does not configure logging at rest on the domain.", resourceBlock)
				return
			}

			logOptions := resourceBlock.GetBlocks("log_publishing_options")
			for _, logOption := range logOptions {

				if logTypeAttr := logOption.GetAttribute("log_type"); logTypeAttr.IsNil() || logTypeAttr.NotEqual("AUDIT_LOGS") {
					continue
				}

				enabledAttr := logOption.GetAttribute("enabled")
				if enabledAttr.IsNotNil() && enabledAttr.IsFalse() {
					results.Add("Resource explicitly disables logging on the domain.", enabledAttr)
					return
				} else {
					// we have audit logs enabled
					return
				}
			}

			results.Add("Audit logging is not enabled for the domain.", resourceBlock)
			return results
		},
	})
}
