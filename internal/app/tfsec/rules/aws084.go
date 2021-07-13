package rules

import (
	"fmt"

	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/severity"

	"github.com/aquasecurity/tfsec/pkg/provider"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/hclcontext"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

const AWSAWSWorkspaceVolumesEncrypted = "AWS084"
const AWSAWSWorkspaceVolumesEncryptedDescription = "Root and user volumes on Workspaces should be encrypted"
const AWSAWSWorkspaceVolumesEncryptedImpact = "Data can be freely read if compromised"
const AWSAWSWorkspaceVolumesEncryptedResolution = "Root and user volume encryption should be enabled"
const AWSAWSWorkspaceVolumesEncryptedExplanation = `
Workspace volumes for both user and root should be encrypted to protect the data stored on them.
`
const AWSAWSWorkspaceVolumesEncryptedBadExample = `
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
`
const AWSAWSWorkspaceVolumesEncryptedGoodExample = `	
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
`

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		ID: AWSAWSWorkspaceVolumesEncrypted,
		Documentation: rule.RuleDocumentation{
			Summary:     AWSAWSWorkspaceVolumesEncryptedDescription,
			Explanation: AWSAWSWorkspaceVolumesEncryptedExplanation,
			Impact:      AWSAWSWorkspaceVolumesEncryptedImpact,
			Resolution:  AWSAWSWorkspaceVolumesEncryptedResolution,
			BadExample:  AWSAWSWorkspaceVolumesEncryptedBadExample,
			GoodExample: AWSAWSWorkspaceVolumesEncryptedGoodExample,
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/workspaces_workspace#root_volume_encryption_enabled",
				"https://docs.aws.amazon.com/workspaces/latest/adminguide/encrypt-workspaces.html",
			},
		},
		Provider:        provider.AWSProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_workspaces_workspace"},
		DefaultSeverity: severity.High,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ *hclcontext.Context) {

			if resourceBlock.MissingChild("root_volume_encryption_enabled") {
				set.Add(
					result.New(resourceBlock).
						WithDescription(fmt.Sprintf("Resource '%s' should have root volume encryption enables", resourceBlock.FullName())).
						WithRange(resourceBlock.Range()),
				)
			} else {
				attr := resourceBlock.GetAttribute("root_volume_encryption_enabled")
				if attr != nil && attr.IsFalse() {
					set.Add(result.New(resourceBlock).
						WithDescription(fmt.Sprintf("Resource '%s' has the root volume encryption set to false", resourceBlock.FullName())).
						WithRange(attr.Range()).
						WithAttributeAnnotation(attr),
					)
				}
			}

			if resourceBlock.MissingChild("user_volume_encryption_enabled") {
				set.Add(result.New(resourceBlock).
					WithDescription(fmt.Sprintf("Resource '%s' should have user volume encryption enables", resourceBlock.FullName())).
					WithRange(resourceBlock.Range()),
				)
				return
			}

			attr := resourceBlock.GetAttribute("user_volume_encryption_enabled")
			if attr != nil && attr.IsFalse() {
				set.Add(
					result.New(resourceBlock).
						WithDescription(fmt.Sprintf("Resource '%s' has the user volume encryption set to false", resourceBlock.FullName())).
						WithRange(attr.Range()).
						WithAttributeAnnotation(attr),
				)
			}

		},
	})
}
