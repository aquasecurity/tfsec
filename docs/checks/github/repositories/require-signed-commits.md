---
title: require-signed-commits
---

### Explanation

You can do this setting the <code>require_signed_commits</code> attribute to 'true'.

### Possible Impact
You cannot guarantee the source of unsigned commits.

### Suggested Resolution
Require signed commits for all protected branches.


### Insecure Example

The following example will fail the github-repositories-require-signed-commits check.

```terraform

resource "github_branch_protection" "bad_example" {
  repository_id = github_repository.example.node_id
  
  pattern          = "main"
  enforce_admins   = true
  allows_deletions = true
  require_signed_commits = false
}

```



### Secure Example

The following example will pass the github-repositories-require-signed-commits check.

```terraform

resource "github_branch_protection" "good_example" {
  repository_id = github_repository.example.node_id
  pattern          = "main"
  enforce_admins   = true
  allows_deletions = true
  require_signed_commits = true
}

```




### Related Links


- [https://registry.terraform.io/providers/hashicorp/github/latest/docs/resources/branch_protection#require_signed_commits](https://registry.terraform.io/providers/hashicorp/github/latest/docs/resources/branch_protection#require_signed_commits){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.github.com/en/authentication/managing-commit-signature-verification/about-commit-signature-verification](https://docs.github.com/en/authentication/managing-commit-signature-verification/about-commit-signature-verification){:target="_blank" rel="nofollow noreferrer noopener"}


