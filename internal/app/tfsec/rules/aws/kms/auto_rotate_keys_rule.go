package kms

import (
	"github.com/aquasecurity/defsec/rules/aws/kms"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID: "AWS019",
		BadExample: []string{`
 resource "aws_kms_key" "bad_example" {
 	enable_key_rotation = false
 }
 `},
		GoodExample: []string{`
 resource "aws_kms_key" "good_example" {
 	enable_key_rotation = true
 }
 `},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/kms_key#enable_key_rotation",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_kms_key"},
		Base:           kms.CheckAutoRotateKeys,
	})
}
