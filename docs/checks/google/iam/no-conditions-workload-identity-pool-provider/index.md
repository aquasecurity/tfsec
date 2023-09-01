---
title: A configuration for an external workload identity pool provider should have conditions set
---

# A configuration for an external workload identity pool provider should have conditions set

### Default Severity: <span class="severity high">high</span>

### Explanation

In GitHub Actions, one can authenticate to Google Cloud by setting values for `workload_identity_provider` and `service_account` and requesting a short-lived OIDC token which is then used to execute commands as that Service Account. If you don't specify a condition in the workload identity provider pool configuration, then any GitHub Action can assume this role and act as that Service Account.

### Possible Impact
Allows an external attacker to authenticate as the attached service account and act with its permissions

### Suggested Resolution
Set conditions on this provider, for example by restricting it to only be allowed from repositories in your GitHub organization


### Insecure Example

The following example will fail the google-iam-no-conditions-workload-identity-pool-provider check.
```terraform

  resource "google_iam_workload_identity_pool" "github" {
    provider = google
    project  = data.google_project.project.project_id
    workload_identity_pool_id = "github"
  }

  resource "google_iam_workload_identity_pool_provider" "github" {
    provider = google
    project  = data.google_project.project.project_id
    workload_identity_pool_id          = google_iam_workload_identity_pool.github-actions[0].workload_identity_pool_id
    workload_identity_pool_provider_id = "github"

    attribute_mapping = {
      "google.subject"       = "assertion.sub"
      "attribute.actor"      = "assertion.actor"
      "attribute.aud"        = "assertion.aud"
      "attribute.repository" = "assertion.repository"
    }

    oidc {
      issuer_uri = "https://token.actions.githubusercontent.com"
    }
  }

```



### Secure Example

The following example will pass the google-iam-no-conditions-workload-identity-pool-provider check.
```terraform

  resource "google_iam_workload_identity_pool" "github" {
    provider = google
    project  = data.google_project.project.project_id
    workload_identity_pool_id = "github"
  }

  resource "google_iam_workload_identity_pool_provider" "github" {
    provider = google
    project  = data.google_project.project.project_id
    workload_identity_pool_id          = google_iam_workload_identity_pool.github-actions[0].workload_identity_pool_id
    workload_identity_pool_provider_id = "github"

    attribute_condition = "assertion.repository_owner=='your-github-organization'"

    attribute_mapping = {
      "google.subject"       = "assertion.sub"
      "attribute.actor"      = "assertion.actor"
      "attribute.aud"        = "assertion.aud"
      "attribute.repository" = "assertion.repository"
    }

    oidc {
      issuer_uri = "https://token.actions.githubusercontent.com"
    }
  }

```



### Links


- [https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/iam_workload_identity_pool_provider#attribute_condition](https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/iam_workload_identity_pool_provider#attribute_condition){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://www.revblock.dev/exploiting-misconfigured-google-cloud-service-accounts-from-github-actions/](https://www.revblock.dev/exploiting-misconfigured-google-cloud-service-accounts-from-github-actions/){:target="_blank" rel="nofollow noreferrer noopener"}



