---
title: GitHub branch protection does not require signed commits.
---

# GitHub branch protection does not require signed commits.

### Default Severity: <span class="severity high">high</span>

### Explanation

GitHub branch protection should be set to require signed commits.

You can do this by setting the <code>require_signed_commits</code> attribute to 'true'.

### Possible Impact
Commits may not be verified and signed as coming from a trusted developer

### Suggested Resolution
Require signed commits


### Insecure Example

The following example will fail the github-branch_protections-require_signed_commits check.
```terraform

 resource "github_branch_protection" "good_example" {
   repository_id = "example"
   pattern       = "main"

   require_signed_commits = false
 }
 
```



### Secure Example

The following example will pass the github-branch_protections-require_signed_commits check.
```terraform

 resource "github_branch_protection" "good_example" {
   repository_id = "example"
   pattern       = "main"

   require_signed_commits = true
 }
 
```



### Links


- [https://registry.terraform.io/providers/integrations/github/latest/docs/resources/branch_protection](https://registry.terraform.io/providers/integrations/github/latest/docs/resources/branch_protection){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://registry.terraform.io/providers/integrations/github/latest/docs/resources/branch_protection#require_signed_commits](https://registry.terraform.io/providers/integrations/github/latest/docs/resources/branch_protection#require_signed_commits){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.github.com/en/authentication/managing-commit-signature-verification/about-commit-signature-verification](https://docs.github.com/en/authentication/managing-commit-signature-verification/about-commit-signature-verification){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/defining-the-mergeability-of-pull-requests/about-protected-branches#require-signed-commits](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/defining-the-mergeability-of-pull-requests/about-protected-branches#require-signed-commits){:target="_blank" rel="nofollow noreferrer noopener"}



