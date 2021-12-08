package iam

import (
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/provider"
	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/rule"
	"github.com/aquasecurity/tfsec/pkg/severity"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID:  "",
		Service:   "iam",
		ShortCode: "enforce-mfa",
		Documentation: rule.RuleDocumentation{
			Summary:    "IAM Groups should have MFA enforcement activated.",
			Impact:     "User accounts are more vulnerable to compromise without multi factor authentication activated",
			Resolution: "Use terraform-module/enforce-mfa/aws to ensure that MFA is enforced",
			Explanation: `
IAM user accounts should be protected with multi factor authentication to add safe guards to password compromise.
			`,
			BadExample: []string{`
data aws_caller_identity current {}

resource aws_iam_group support {
  name =  "support"
}

resource aws_iam_group developers {
  name =  "developers"
}
`, `
data aws_caller_identity current {}

resource aws_iam_group support {
  name =  "support"
}

resource aws_iam_group developers {
  name =  "developers"
}

module enforce_mfa {
  source  = "terraform-module/enforce-mfa/aws"
  version = "0.12.0"

  policy_name                     = "managed-mfa-enforce"
  account_id                      = data.aws_caller_identity.current.id
  groups                          = [aws_iam_group.support.name]
  manage_own_signing_certificates  = true
  manage_own_ssh_public_keys      = true
  manage_own_git_credentials      = true
}
`},
			GoodExample: []string{`
data aws_caller_identity current {}

resource aws_iam_group support {
  name =  "support"
}

module enforce_mfa {
  source  = "terraform-module/enforce-mfa/aws"
  version = "0.12.0"

  policy_name                     = "managed-mfa-enforce"
  account_id                      = data.aws_caller_identity.current.id
  groups                          = [aws_iam_group.support.name]
  manage_own_signing_certificates  = true
  manage_own_ssh_public_keys      = true
  manage_own_git_credentials      = true
}
`},
			Links: []string{
				"https://registry.terraform.io/modules/terraform-module/enforce-mfa/aws/latest",
				"https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html#password-policy-details",
			},
		},
		Provider:        provider.AWSProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_iam_group"},
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, resourceBlock block.Block, module block.Module) {
			blocks, err := module.GetsModulesBySource("terraform-module/enforce-mfa/aws")
			if err != nil || len(blocks) == 0 {
				set.AddResult().
					WithDescription("Resource %s has no associated MFA enforcement block.", resourceBlock.FullName())
			}

			for _, moduleBlock := range blocks {
				groupsAttr := moduleBlock.GetAttribute("groups")
				if groupsAttr.IsNil() {
					continue
				}
				if groupsAttr.ReferencesBlock(resourceBlock) {
					return
				}
			}
			set.AddResult().
				WithDescription("Resource %s has no associated MFA enforcement block.", resourceBlock.FullName())
		},
	})
}
