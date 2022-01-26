---
title: KMS keys should be rotated at least every 90 days
---

# KMS keys should be rotated at least every 90 days

### Default Severity: <span class="severity high">high</span>

### Explanation

Keys should be rotated on a regular basis to limit exposure if a given key should become compromised.

### Possible Impact
Exposure is greater if the same keys are used over a long period

### Suggested Resolution
Set key rotation period to 90 days


### Insecure Example

The following example will fail the google-kms-rotate-kms-keys check.
```terraform

 resource "google_kms_key_ring" "keyring" {
   name     = "keyring-example"
   location = "global"
 }
 
 resource "google_kms_crypto_key" "example-key" {
   name            = "crypto-key-example"
   key_ring        = google_kms_key_ring.keyring.id
   rotation_period = "15552000s"
 
   lifecycle {
     prevent_destroy = true
   }
 }
 
```



### Secure Example

The following example will pass the google-kms-rotate-kms-keys check.
```terraform

 resource "google_kms_key_ring" "keyring" {
   name     = "keyring-example"
   location = "global"
 }
 
 resource "google_kms_crypto_key" "example-key" {
   name            = "crypto-key-example"
   key_ring        = google_kms_key_ring.keyring.id
   rotation_period = "7776000s"
 
   lifecycle {
     prevent_destroy = true
   }
 }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/kms_crypto_key#rotation_period](https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/kms_crypto_key#rotation_period){:target="_blank" rel="nofollow noreferrer noopener"}



