---
title: In Module Checking
permalink: /docs/check_library/in_module/
---

In module check is useful if you want to ensure that a resource is in a module.

Take, for example, a company requirement that all S3 buckets are created using the corporate S3 bucket module. This module ensures the encryption, logging and permission requirements conform to the corporate policy.

We might want to ensure that any `aws_s3_bucket` encountered by tfsec is inside a module.

```json
{
  "code": "CUS004",
  "description": "Custom check to ensure S3 buckets are only created using the custom_bucket module",
  "requiredTypes": [
    "resource"
  ],
  "requiredLabels": [
    "aws_s3_bucket"
  ],
  "severity": "ERROR",
  "matchSpec": {
    "action": "inModule"
  },
  "errorMessage": "S3 buckets must only be created using the custom bucket module",
  "relatedLinks": [
    "http://internal.acmecorp.com/standards/aws/s3_buckets.html"
  ]
}
```