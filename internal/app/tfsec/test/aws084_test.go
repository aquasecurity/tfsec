package test

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/rules"
)

func Test_AWSAWSWorkspaceVolumesEncrypted(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "Root and user encryption not set fails check",
			source: `
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
`,
			mustIncludeResultCode: rules.AWSAWSWorkspaceVolumesEncrypted,
		},
		{
			name: "User encryption not set fails check",
			source: `
resource "aws_workspaces_workspace" "bad_example" {
	directory_id = aws_workspaces_directory.test.id
	bundle_id    = data.aws_workspaces_bundle.value_windows_10.id
	user_name    = "Administrator"

	root_volume_encryption_enabled = true
  
	workspace_properties {
	  compute_type_name                         = "VALUE"
	  user_volume_size_gib                      = 10
	  root_volume_size_gib                      = 80
	  running_mode                              = "AUTO_STOP"
	  running_mode_auto_stop_timeout_in_minutes = 60
	}
  }
`,
			mustIncludeResultCode: rules.AWSAWSWorkspaceVolumesEncrypted,
		},
		{
			name: "Root encryption not set fails check",
			source: `
resource "aws_workspaces_workspace" "bad_example" {
	directory_id = aws_workspaces_directory.test.id
	bundle_id    = data.aws_workspaces_bundle.value_windows_10.id
	user_name    = "Administrator"

	user_volume_encryption_enabled = true
  
	workspace_properties {
	  compute_type_name                         = "VALUE"
	  user_volume_size_gib                      = 10
	  root_volume_size_gib                      = 80
	  running_mode                              = "AUTO_STOP"
	  running_mode_auto_stop_timeout_in_minutes = 60
	}
  }
`,
			mustIncludeResultCode: rules.AWSAWSWorkspaceVolumesEncrypted,
		},
		{
			name: "Root encryption set to false fails check",
			source: `
resource "aws_workspaces_workspace" "bad_example" {
	directory_id = aws_workspaces_directory.test.id
	bundle_id    = data.aws_workspaces_bundle.value_windows_10.id
	user_name    = "Administrator"

	user_volume_encryption_enabled = false
  
	workspace_properties {
	  compute_type_name                         = "VALUE"
	  user_volume_size_gib                      = 10
	  root_volume_size_gib                      = 80
	  running_mode                              = "AUTO_STOP"
	  running_mode_auto_stop_timeout_in_minutes = 60
	}
  }
`,
			mustIncludeResultCode: rules.AWSAWSWorkspaceVolumesEncrypted,
		},
		{
			name: "Root and user encryption enable passes check",
			source: `
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
`,
			mustExcludeResultCode: rules.AWSAWSWorkspaceVolumesEncrypted,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
