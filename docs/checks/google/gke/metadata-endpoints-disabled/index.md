---
title: Legacy metadata endpoints enabled.
---

# Legacy metadata endpoints enabled.

### Default Severity: <span class="severity high">high</span>

### Explanation

The Compute Engine instance metadata server exposes legacy v0.1 and v1beta1 endpoints, which do not enforce metadata query headers. 

This is a feature in the v1 APIs that makes it more difficult for a potential attacker to retrieve instance metadata. 

Unless specifically required, we recommend you disable these legacy APIs.

When setting the <code>metadata</code> block, the default value for <code>disable-legacy-endpoints</code> is set to true, they should not be explicitly enabled.

### Possible Impact
Legacy metadata endpoints don't require metadata headers

### Suggested Resolution
Disable legacy metadata endpoints


### Insecure Example

The following example will fail the google-gke-metadata-endpoints-disabled check.
```terraform

 resource "google_container_cluster" "bad_example" {
    node_config {
      metadata = {
        disable-legacy-endpoints = false
      }
    }
 }
```



### Secure Example

The following example will pass the google-gke-metadata-endpoints-disabled check.
```terraform

 resource "google_container_cluster" "good_example" {
    node_config {
      metadata = {
        disable-legacy-endpoints = true
      }
    }
 }
```



### Links


- [https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/container_cluster#metadata](https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/container_cluster#metadata){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster#protect_node_metadata_default_for_112](https://cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster#protect_node_metadata_default_for_112){:target="_blank" rel="nofollow noreferrer noopener"}



