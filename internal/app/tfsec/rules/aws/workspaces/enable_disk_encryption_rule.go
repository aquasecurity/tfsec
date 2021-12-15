package workspaces

import (
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/rules/aws/workspaces"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID: "AWS084",
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
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_workspaces_workspace"},
		Base:           workspaces.CheckEnableDiskEncryption,
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {

			if resourceBlock.MissingChild("root_volume_encryption_enabled") {
				results.Add("Resource should have root volume encryption enabled", resourceBlock)
			} else {
				rootVolEncAttr := resourceBlock.GetAttribute("root_volume_encryption_enabled")
				if rootVolEncAttr.IsNotNil() && rootVolEncAttr.IsFalse() {
					results.Add("Resource has the root volume encryption set to false", rootVolEncAttr)
				}
			}

			if resourceBlock.MissingChild("user_volume_encryption_enabled") {
				results.Add("Resource should have user volume encryption enabled", resourceBlock)
				return
			}

			userVolEncAttr := resourceBlock.GetAttribute("user_volume_encryption_enabled")
			if userVolEncAttr.IsNotNil() && userVolEncAttr.IsFalse() {
				results.Add("Resource has the user volume encryption set to false", userVolEncAttr)
			}

			return results
		},
	})
}
