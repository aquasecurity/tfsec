---
title: ACL Checking
permalink: /docs/check_library/acls/

This check is useful when there are specific ACLs on `aws_s3_buckets` that you absolutely don't want to be used.

For this, the `isNone` check action works well, you can provide a list of values that must not be used. In the example below, if the `acl` attribute is one of the list, the check will fail.



```json
{
  "code": "CUS003",
  "description": "Check ACL is not one of bad values",
  "requiredTypes": [
    "resource"
  ],
  "requiredLabels": [
    "aws_s3_bucket"
  ],
  "severity": "ERROR",
  "matchSpec": {
    "name": "acl",
    "value": ["public-read", "authenticated-users"],
    "action": "isNone"
  },
  "errorMessage": "The ACL must not be one of ['public-read', 'authenticated-users']",
  "relatedLinks": [
    "http://internal.acmecorp.com/standards/aws/tagging.html"
  ]
}
```