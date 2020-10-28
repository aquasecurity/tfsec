---
title: Tag Checking
permalink: /docs/check_library/tagged/
---

Tag checking allows us to ensure that Terraform confirms to company compliance requirements.

Take, for example, a requirement that all assets must be tagged as with a `CostCentre` for tracking expenditure.

The custom check below can be used;

```json
{
  "code": "CUS001",
  "description": "Custom check to ensure the CostCentre tag is applied to EC2 instances",
  "requiredTypes": [
    "resource"
  ],
  "requiredLabels": [
    "aws_instance"
  ],
  "severity": "ERROR",
  "matchSpec": {
    "name": "tags",
    "action": "contains",
    "value": "CostCentre"
  },
  "errorMessage": "The required CostCentre tag was missing",
  "relatedLinks": [
    "http://internal.acmecorp.com/standards/aws/tagging.html"
  ]
}
```