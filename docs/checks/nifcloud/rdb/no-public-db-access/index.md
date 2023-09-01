---
title: A database resource is marked as publicly accessible.
---

# A database resource is marked as publicly accessible.

### Default Severity: <span class="severity critical">critical</span>

### Explanation

Database resources should not publicly available. You should limit all access to the minimum that is required for your application to function.

### Possible Impact
The database instance is publicly accessible

### Suggested Resolution
Set the database to not be publicly accessible


### Insecure Example

The following example will fail the nifcloud-rdb-no-public-db-access check.
```terraform

 resource "nifcloud_db_instance" "bad_example" {
 	publicly_accessible = true
 }
 
```



### Secure Example

The following example will pass the nifcloud-rdb-no-public-db-access check.
```terraform

 resource "nifcloud_db_instance" "good_example" {
 	publicly_accessible = false
 }
 
```



### Links


- [https://registry.terraform.io/providers/nifcloud/nifcloud/latest/docs/resources/db_instance#publicly_accessible](https://registry.terraform.io/providers/nifcloud/nifcloud/latest/docs/resources/db_instance#publicly_accessible){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://pfs.nifcloud.com/guide/rdb/server_new.htm](https://pfs.nifcloud.com/guide/rdb/server_new.htm){:target="_blank" rel="nofollow noreferrer noopener"}



