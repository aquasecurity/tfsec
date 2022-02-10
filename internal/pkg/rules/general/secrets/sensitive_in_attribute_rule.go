package secrets

import (
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/rules/general/secrets"
	"github.com/zclconf/go-cty/cty"

	"github.com/aquasecurity/trivy-config-parsers/terraform"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/aquasecurity/tfsec/internal/pkg/security"

	"github.com/aquasecurity/tfsec/internal/pkg/scanner"
)

var sensitiveWhitelist = []struct {
	Resource  string
	Attribute string
}{
	{
		Resource:  "aws_efs_file_system",
		Attribute: "creation_token",
	},
	{
		Resource:  "aws_instance",
		Attribute: "get_password_data",
	},
	{
		Resource:  "github_actions_secret",
		Attribute: "secret_name",
	},
	{
		Resource:  "github_actions_organization_secret",
		Attribute: "secret_name",
	},
	{
		Resource:  "google_secret_manager_secret",
		Attribute: "secret_id",
	},
	{
		Resource:  "google_secret_manager_secret_iam_member",
		Attribute: "secret_id",
	},
	{
		Resource:  "vault_pki_secret_backend_cert",
		Attribute: "private_key_format",
	},
	{
		Resource:  "kubernetes_service_account",
		Attribute: "automount_service_account_token",
	},
}

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		RequiredTypes: []string{"resource", "provider", "module"},
		Base:          secrets.CheckNotExposed,
		CheckTerraform: func(resourceBlock *terraform.Block, _ *terraform.Module) (results rules.Results) {

			attributes := resourceBlock.GetAttributes()

		SKIP:
			for _, attribute := range attributes {
				for _, whitelisted := range sensitiveWhitelist {
					if whitelisted.Resource == resourceBlock.TypeLabel() && whitelisted.Attribute == attribute.Name() {
						continue SKIP
					}
				}
				if security.IsSensitiveAttribute(attribute.Name()) {
					if attribute.IsResolvable() && attribute.Type() == cty.String && !attribute.Equals("") {
						results.Add(
							"Attribute name appears sensitive and has a value which is defined within the project.",
							attribute,
						)
					}

				}
			}
			return results
		},
	})
}
