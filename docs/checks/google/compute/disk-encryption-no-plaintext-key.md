---
title: The encryption key used to encrypt a compute disk has been specified in plaintext.
---

# The encryption key used to encrypt a compute disk has been specified in plaintext.

### Default Severity: <span class="severity critical">critical</span>

### Explanation

Sensitive values such as raw encryption keys should not be included in your Terraform code, and should be stored securely by a secrets manager.

### Possible Impact
The encryption key should be considered compromised as it is not stored securely.

### Suggested Resolution
Reference a managed key rather than include the key in raw format.


### Insecure Example

The following example will fail the google-compute-disk-encryption-no-plaintext-key check.
```terraform

 resource "google_compute_disk" "good_example" {
 	disk_encryption_key {
 		raw_key="b2ggbm8gdGhpcyBpcyBiYWQ="
 	}
 }
 
```



### Secure Example

The following example will pass the google-compute-disk-encryption-no-plaintext-key check.
```terraform

 resource "google_compute_disk" "good_example" {
 	disk_encryption_key {
 		kms_key_self_link = google_kms_crypto_key.my_crypto_key.id
 	}
 }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_disk#kms_key_self_link](https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_disk#kms_key_self_link){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://cloud.google.com/compute/docs/disks/customer-supplied-encryption](https://cloud.google.com/compute/docs/disks/customer-supplied-encryption){:target="_blank" rel="nofollow noreferrer noopener"}



