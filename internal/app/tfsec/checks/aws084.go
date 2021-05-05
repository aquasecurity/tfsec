package checks

import (
	"fmt"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

const AWSAWSWorkspaceVolumesEncrypted scanner.RuleCode = "AWS084"
const AWSAWSWorkspaceVolumesEncryptedDescription scanner.RuleSummary = "Root and user volumes on Workspaces should be encrypted"
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
}
`

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code: AWSAWSWorkspaceVolumesEncrypted,
		Documentation: scanner.CheckDocumentation{
			Summary:     AWSAWSWorkspaceVolumesEncryptedDescription,
			Explanation: AWSAWSWorkspaceVolumesEncryptedExplanation,
			Impact:      AWSAWSWorkspaceVolumesEncryptedImpact,
			Resolution:  AWSAWSWorkspaceVolumesEncryptedResolution,
			BadExample:  AWSAWSWorkspaceVolumesEncryptedBadExample,
			GoodExample: AWSAWSWorkspaceVolumesEncryptedGoodExample,
			Links:       []string{},
		},
		Provider:       scanner.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_workspaces_workspace"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {

			if block.MissingChild("root_volume_encryption_enabled") {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' should have root volume encryption enables", block.FullName()),
						block.Range(),
						scanner.SeverityError,
					),
				}
			} else {
				attr := block.GetAttribute("root_volume_encryption_enabled")
				if attr.IsFalse() {
					return []scanner.Result{
						check.NewResultWithValueAnnotation(
							fmt.Sprintf("Resource '%s' has the root volumnet encyption set to false", block.FullName()),
							attr.Range(),
							attr,
							scanner.SeverityError,
						),
					}
				}
			}

			if block.MissingChild("user_volume_encryption_enabled") {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' should have user volume encryption enables", block.FullName()),
						block.Range(),
						scanner.SeverityError,
					),
				}
			} else {
				attr := block.GetAttribute("user_volume_encryption_enabled")
				if attr.IsFalse() {
					return []scanner.Result{
						check.NewResultWithValueAnnotation(
							fmt.Sprintf("Resource '%s' has the user volumnet encyption set to false", block.FullName()),
							attr.Range(),
							attr,
							scanner.SeverityError,
						),
					}
				}
			}

			return nil
		},
	})
}
