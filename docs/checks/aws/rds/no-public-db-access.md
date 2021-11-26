---
title: no-public-db-access
---

### Explanation


Database resources should not publicly available. You should limit all access to the minimum that is required for your application to function. 


### Possible Impact
The database instance is publicly accessible

### Suggested Resolution
Set the database to not be publicly accessible


### Insecure Example

The following example will fail the aws-rds-no-public-db-access check.

```terraform

resource "aws_db_instance" "bad_example" {
	publicly_accessible = true
}

```



### Secure Example

The following example will pass the aws-rds-no-public-db-access check.

```terraform

resource "aws_db_instance" "good_example" {
	publicly_accessible = false
}

```




### Related Links


- [https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/db_instance](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/db_instance){:target="_blank" rel="nofollow noreferrer noopener"}


