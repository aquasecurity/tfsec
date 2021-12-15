package ssm

// generator-locked
import (
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/pkg/rule"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID: "AWS095",
		BadExample: []string{`
 resource "aws_secretsmanager_secret" "bad_example" {
   name       = "lambda_password"
 }
 `},
		GoodExample: []string{`
 resource "aws_kms_key" "secrets" {
 	enable_key_rotation = true
 }
 
 resource "aws_secretsmanager_secret" "good_example" {
   name       = "lambda_password"
   kms_key_id = aws_kms_key.secrets.arn
 }
 `},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/secretsmanager_secret#kms_key_id",
			"https://docs.aws.amazon.com/kms/latest/developerguide/services-secrets-manager.html#asm-encrypt",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_secretsmanager_secret"},
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {

			if resourceBlock.MissingChild("kms_key_id") {
				results.Add("Resource does not use CMK", resourceBlock)
				return
			}

			kmsKeyAttr := resourceBlock.GetAttribute("kms_key_id")
			if kmsKeyAttr.IsDataBlockReference() {
				kmsData, err := module.GetReferencedBlock(kmsKeyAttr, resourceBlock)
				if err != nil {
					return
				}
				keyIdAttr := kmsData.GetAttribute("key_id")
				if keyIdAttr.IsNotNil() && keyIdAttr.Equals("alias/aws/secretsmanager") {
					results.Add("Resource explicitly uses the default CMK", ?)
				}
			}

			return results
		},
	})
}
