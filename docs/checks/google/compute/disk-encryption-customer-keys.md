---
title: disk-encryption-customer-keys
---

### Explanation


By default, Compute Engine encrypts all data at rest. Compute Engine handles and manages this encryption for you without any additional actions on your part.

If the <code>disk_encryption_key</code> block is included in the resource declaration then it *must* include a <code>raw_key</code> or <code>kms_key_self_link</code>.


### Possible Impact
Encryption of disk using unmanaged keys.

### Suggested Resolution
Enable encryption using a customer-managed key.


### Insecure Example

The following example will fail the google-compute-disk-encryption-customer-keys check.

```terraform

resource "google_compute_disk" "bad_example" {
	# ...
}
```



### Secure Example

The following example will pass the google-compute-disk-encryption-customer-keys check.

```terraform

resource "google_compute_disk" "good_example" {
	disk_encryption_key {
		kms_key_self_link = "something"
	}
}


```




### Related Links


- [https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_disk](https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_disk){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://cloud.google.com/compute/docs/disks/customer-supplied-encryption](https://cloud.google.com/compute/docs/disks/customer-supplied-encryption){:target="_blank" rel="nofollow noreferrer noopener"}


