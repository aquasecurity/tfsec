package sns

import (
	"github.com/aquasecurity/defsec/rules/aws/sns"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID: "AWS016",
		BadExample: []string{`
 resource "aws_sns_topic" "bad_example" {
 	# no key id specified
 }
 `},
		GoodExample: []string{`
 resource "aws_sns_topic" "good_example" {
 	kms_master_key_id = "/blah"
 }
 `},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/sns_topic#example-with-server-side-encryption-sse",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_sns_topic"},
		Base:           sns.CheckEnableTopicEncryption,
	})
}
