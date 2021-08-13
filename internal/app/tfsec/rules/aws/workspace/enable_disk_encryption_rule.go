package workspace

// generator-locked
import (
	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/severity"

	"github.com/aquasecurity/tfsec/pkg/provider"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID:  "AWS084",
		Service:   "workspace",
		ShortCode: "enable-disk-encryption",
		Documentation: rule.RuleDocumentation{
			Summary: "Root and user volumes on Workspaces should be encrypted",
			Explanation: `
Workspace volumes for both user and root should be encrypted to protect the data stored on them.
`,
			Impact:     "Data can be freely read if compromised",
			Resolution: "Root and user volume encryption should be enabled",
			BadExample: []string{`
resource "aws_workspaces_workspace" "bad_example" {
	directory_id = aws_workspaces_directory.test.id
	bundle_id    = data.aws_workspaces_bundle.value_windows_10.id
	user_name    = "Administrator"
  
	workspace_properties {
	  compute_type_name                         = "VALUE"
	  user_volume_size_gib                      = 10
	  root_volume_size_gib                      = 80
	  running_mode                              = "AUTO_STOP"
	  running_mode_auto_stop_timeout_in_minutes = 60
	}
  }
`},
			GoodExample: []string{`	
resource "aws_workspaces_workspace" "good_example" {
		directory_id 				   = aws_workspaces_directory.test.id
		bundle_id    				   = data.aws_workspaces_bundle.value_windows_10.id
		user_name    				   = "Administrator"
		root_volume_encryption_enabled = true
		user_volume_encryption_enabled = true
	  
		workspace_properties {
		  compute_type_name                         = "VALUE"
		  user_volume_size_gib                      = 10
		  root_volume_size_gib                      = 80
		  running_mode                              = "AUTO_STOP"
		  running_mode_auto_stop_timeout_in_minutes = 60
		}
}
`},
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/workspaces_workspace#root_volume_encryption_enabled",
				"https://docs.aws.amazon.com/workspaces/latest/adminguide/encrypt-workspaces.html",
			},
		},
		Provider:        provider.AWSProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_workspaces_workspace"},
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ block.Module) {

			if resourceBlock.MissingChild("root_volume_encryption_enabled") {
				set.AddResult().
					WithDescription("Resource '%s' should have root volume encryption enabled", resourceBlock.FullName())
			} else {
				rootVolEncAttr := resourceBlock.GetAttribute("root_volume_encryption_enabled")
				if rootVolEncAttr.IsNotNil() && rootVolEncAttr.IsFalse() {
					set.AddResult().
						WithDescription("Resource '%s' has the root volume encryption set to false", resourceBlock.FullName()).
						WithAttribute(rootVolEncAttr)
				}
			}

			if resourceBlock.MissingChild("user_volume_encryption_enabled") {
				set.AddResult().
					WithDescription("Resource '%s' should have user volume encryption enabled", resourceBlock.FullName())
				return
			}

			userVolEncAttr := resourceBlock.GetAttribute("user_volume_encryption_enabled")
			if userVolEncAttr.IsNotNil() && userVolEncAttr.IsFalse() {
				set.AddResult().
					WithDescription("Resource '%s' has the user volume encryption set to false", resourceBlock.FullName()).
					WithAttribute(userVolEncAttr)
			}

		},
	})
}
