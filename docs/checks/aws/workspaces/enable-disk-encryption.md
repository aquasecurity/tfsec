---
title: Root and user volumes on Workspaces should be encrypted
---

# Root and user volumes on Workspaces should be encrypted

### Default Severity: <span class="severity high">high</span>

### Explanation

Workspace volumes for both user and root should be encrypted to protect the data stored on them.

### Possible Impact
Data can be freely read if compromised

### Suggested Resolution
Root and user volume encryption should be enabled


### Insecure Example

The following example will fail the aws-workspaces-enable-disk-encryption check.
```terraform

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
 
```



### Secure Example

The following example will pass the aws-workspaces-enable-disk-encryption check.
```terraform
	
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
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/workspaces_workspace#root_volume_encryption_enabled](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/workspaces_workspace#root_volume_encryption_enabled){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.aws.amazon.com/workspaces/latest/adminguide/encrypt-workspaces.html](https://docs.aws.amazon.com/workspaces/latest/adminguide/encrypt-workspaces.html){:target="_blank" rel="nofollow noreferrer noopener"}



