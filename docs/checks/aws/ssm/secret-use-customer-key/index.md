---
title: Secrets Manager should use customer managed keys
---

# Secrets Manager should use customer managed keys

### Default Severity: <span class="severity low">low</span>

### Explanation

Secrets Manager encrypts secrets by default using a default key created by AWS. To ensure control and granularity of secret encryption, CMK's should be used explicitly.

### Possible Impact
Using AWS managed keys reduces the flexibility and control over the encryption key

### Suggested Resolution
Use customer managed keys


### Insecure Example

The following example will fail the aws-ssm-secret-use-customer-key check.
```terraform

 resource "aws_secretsmanager_secret" "bad_example" {
   name       = "lambda_password"
 }
 
```



### Secure Example

The following example will pass the aws-ssm-secret-use-customer-key check.
```terraform

 resource "aws_kms_key" "secrets" {
 	enable_key_rotation = true
 }
 
 resource "aws_secretsmanager_secret" "good_example" {
   name       = "lambda_password"
   kms_key_id = aws_kms_key.secrets.arn
 }
 
```



### Links


- [https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/secretsmanager_secret#kms_key_id](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/secretsmanager_secret#kms_key_id){:target="_blank" rel="nofollow noreferrer noopener"}

- [https://docs.aws.amazon.com/kms/latest/developerguide/services-secrets-manager.html#asm-encrypt](https://docs.aws.amazon.com/kms/latest/developerguide/services-secrets-manager.html#asm-encrypt){:target="_blank" rel="nofollow noreferrer noopener"}



