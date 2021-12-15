package secrets

generator-locked
import (
"github.com/aquasecurity/defsec/provider"
"github.com/aquasecurity/defsec/rules"
"github.com/aquasecurity/defsec/severity"
"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
"github.com/aquasecurity/tfsec/internal/app/tfsec/security"
"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID: "GEN005",
		Base: rules.Register(rules.Rule{

			Severity: severity.Critical,
		}, nil),
		BadExample: []string{`
 resource "aws_instance" "bad_example" {
 	instance_type = "t2.small"
 
 	user_data = <<EOF
 		Password = "something secret"
 EOF
 
 }
 `},
		GoodExample: []string{`
 variable "password" {
 	type = string
 }
 
 resource "aws_instance" "good_instance" {
 	instance_type = "t2.small"
 
 	user_data = <<EOF
 		export EDITOR=vimacs
 EOF
 
 }
 `},
		Links: []string{
			"https://www.terraform.io/docs/state/sensitive-data.html",
		},
		RequiredTypes: []string{"resource", "provider", "module", "locals", "variable"},
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {
			attributes := resourceBlock.GetAttributes()
			for _, attribute := range attributes {
				if attribute.IsString() {
					if scanResult := security.StringScanner.Scan(attribute.Value().AsString()); scanResult.TransgressionFound {
						results.Add(
							"A potentially sensitive string was discovered within an attribute value.",
							attribute,
						)
					}
				}
			}
			returnreturn
			results
