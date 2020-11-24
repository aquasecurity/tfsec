---
title: Custom Checks
permalink: /docs/custom_checks/
---

## What is it?
tfsec comes with an ever growing number of built in checks, these cover standard AWS, Azure and GCP provider checks, plus several more.

We recognise that there are checks that need performing for an organisation that don't fit with general use cases; for this, there are custom checks.

Custom checks offer an accessible approach to injecting checks that satisfy your organisations compliance and security needs. For example, if you require that all EC2 instances have a `CostCentre` tag, that can be achieved with a `custom_check`.

## How does it work?
Custom checks are defined as json files which sit in the `.tfsec` folder in the root check path. any file with the suffix `_tfchecks.json` or `_tfchecks.yaml` will be parsed and the checks included during the run.


### Overriding check directory
The default location for custom checks can be overridden, this is done using the `--custom-check-dir` to specify another location to load the checks from instead.
This is useful when global checks are to applied to the terraform under test.

### What does a check file look like?
Check files are simply json, this ensures that checks can be put together without requiring Go knowledge or being able to build a new release of tfsec to include your custom code.

Taking the previous example of a required cost centre, the check file might look something like

```json
{
  "checks": [
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
  ]   
}
```

or 

```yaml
---
checks:
- code: CUS001
  description: Custom check to ensure the CostCentre tag is applied to EC2 instances
  requiredTypes:
  - resource
  requiredLabels:
  - aws_instance
  severity: ERROR
  matchSpec:
    name: tags
    action: contains
    value: CostCentre
  errorMessage: The required CostCentre tag was missing
  relatedLinks:
  - http://internal.acmecorp.com/standards/aws/tagging.html

```

The check contains up of the following attributes;

| Attribute | Description |
|:-----------|:-------------|
| code | The custom code that your check will be known as |
| description | A description for the code that will be included in the output|
|requiredTypes | The block types to apply the check to - resource, data, module, variable |
|requiredLabels | The resource type - aws_ec2_instance for example |
|severity | How severe is the check |
|matchSpec | See below for the MatchSpec attributes |
|errorMessage | The error message that should be displayed in cases where the check fails |
|relatedLinks | A list of related links for the check to be displayed in cases where the check fails |


The `MatchSpec` is the what will define the check itself - this is fairly basic and is made up of the following attributes

| Attribute | Description |
|:----------|:------------|
| name | The name of the attribute or block to run the check on |
| action | The check type - see below for more information |
| value | In cases where a value is required, the value to look for |
| ignoreUndefined | If the attribute is undefined, ignore and pass the check |
|subMatch | A sub MatchSpec block for nested checking - think looking for `enabled` value in a `logging` block |

#### Check Actions
There are a number of `CheckActions` available which should allow you to quickly put together most checks.

##### inModule
The `inModule` check action passes if the resource block is a component of a module. For example, if you're looking to check that an `aws_s3_bucket` is only created using a custom module, you could use the following `MatchSpec`;

```json
"matchSpec" : {
  "action": "inModule"
}
```

```yaml
matchSpec:
  action: inModule
```

##### isPresent
The `isPresent` check action passes if the required block or attribute is available in the checked block. For example, if you're looking to check that an `acl` is provided and don't care what it is, you can use the following `MatchSpec`;

```json
"matchSpec" : {
  "name": "acl",
  "action": "isPresent"
}
```

```yaml
matchSpec:
  name: acl
  action: isPresent
```

##### notPresent
Conversely, the `noPresent` check action passes if the specified block or attribute is not found in the checked block. For example, if you explicitly don't want an `acl` attribute to be present hou can use the following `MatchSpec`

```json
"matchSpec" : {
  "name": "acl",
  "action": "notPresent"
}
```

```yaml
matchSpec:
  name: acl
  action: notPresent
```

##### isEmpty
The `isEmpty` check action passes if the named block or attribute is defined by empty.
For example, to check that there are not tags you might use the following `MatchSpec`

```json
"matchSpec" : {
  "name": "tags",
  "action": "isEmpty",
}
```

```yaml
matchSpec:
  name: acl
  action: isEmpty
```

##### startsWith
The `startsWith` check action passes if the checked attribute string starts with the specified value. For example, to check that `acl` begins with `public` you could use the following `MatchSpec`

```json
"matchSpec" : {
  "name": "acl",
  "action": "startsWith",
  "value": "public"
}
```

```yaml
matchSpec:
  name: acl
  action: startsWith
  value: public
```

##### endsWith
The `endsWith` check action passes if the checked attribute string ends with the specified value. For example, to check that `acl` ends with `read` you could use the following `MatchSpec`;

```json
"matchSpec" : {
  "name": "acl",
  "action": "endsWith",
  "value": "-read"
}
```

```yaml
matchSpec:
  name: acl
  action: endsWith
  value: -read
```

##### contains
The `contains` check action will change depending on the attribute or block it is applied to. If the check is against a string attribute, it will look for the `MatchSpec` value in the attribute. If the check is against a list, it will pass if the value item can be found in the list.

If the attribute is an `object` or `map` it will pass if a key can be found that matches the `MatchSpec` value.

For example, if you want to ensure that the `CostCentre` exists, you might use the following `MatchSpec`;

```json
"matchSpec" : {
  "name": "tags",
  "action": "contains",
  "value": "CostCentre"
}
```

```yaml
matchSpec:
  name: tags
  action: contains
  value: CostCentre
```

##### notContains
The `notContains` check action will change depending on the attribute or block it is applied to. If the check is against a string attribute, it will look for the `MatchSpec` value in the attribute. If the check is against a list, it will pass if the value item can be found in the list.

If the attribute is an `object` or `map` it will pass if a key can be found that matches the `MatchSpec` value.

For example, you want to make sure that an `action` does not contain `kms:*` you might use the following `MatchSpec`:

```json
"matchSpec" : {
  "name": "action",
  "action": "notContains",
  "value": "kms:*"
}
```

```yaml
matchSpec:
  name: tags
  action: notContains
  value: kms:*
```

##### equals 
The `equals` check action passes if the checked attribute equals specified value. 
The core primitive types are supported, if the subject attribute is a Boolean, the `MatchSpec` value will attempt to be cast to a Boolean for comparison.
For example, to check that `acl` begins with `private` you could use the following `MatchSpec`;

```json
"matchSpec" : {
  "name": "acl",
  "action": "equals",
  "value": "private"
}
```

```yaml
matchSpec:
  name: acl
  action: equals
  value: private
```

##### lessThan
The `lessThan` check action passes if the checked attribute is numerical and the value is less than the specified value.
For example, if you want to ensure that the `cpu_core_count` is less than 8, you might use the following `MatchSpec`

```json
"matchSpec" : {
  "name": "cpu_core_count",
  "action": "lessThan",
  "value": 8
}
```

```yaml
matchSpec:
  name: cpu_core_count
  action: lessThan
  value: 8
```

##### lessThanOrEqualTo
The `lessThanOrEqualTo` check action passes if the checked attribute is numerical and the value is less than or equal tothe specified value.
For example, if you want to ensure that the `cpu_core_count` is less than or equal to 4, you might use the following `MatchSpec`

```json
"matchSpec" : {
  "name": "cpu_core_count",
  "action": "lessThanOrEqualTo",
  "value": 4
}
```

```yaml
matchSpec:
  name: cpu_core_count
  action: lessThanOrEqualTo
  value: 4
```

##### greaterThan
The `greaterThan` check action passes if the checked attribute is numerical and the value is greater than the specified value.
For example, if you want to ensure that the `cpu_core_count` is greater than 2, you might use the following `MatchSpec`

```json
"matchSpec" : {
  "name": "cpu_core_count",
  "action": "greaterThan",
  "value": 2
}
```

```yaml
matchSpec:
  name: cpu_core_count
  action: greaterThan
  value: 2
```

##### greaterThanOrEqualTo
The `greaterThanOrEqualTo` check action passes if the checked attribute is numerical and the value is greater than or equal tothe specified value.
For example, if you want to ensure that the `cpu_core_count` is greater than or equal to 4, you might use the following `MatchSpec`

```json
"matchSpec" : {
  "name": "cpu_core_count",
  "action": "greaterThanOrEqualTo",
  "value": 4
}
```

```yaml
matchSpec:
  name: cpu_core_count
  action: greaterThanOrEqualTo
  value: 4
```

##### regexMatches
The `regexMatches` check action passes when the regex is matched to the pattern passed in the value. This is check would generally be used as a top level check to filter whether or not to apply a check.

For example, this check will ensure that the source attribute of a module matches the supplied regex before continuing with the subMatches. This can be used to ensure that checks are targetted to specific modules.

When tackling this specific use case of filtering module blocks by source, the `requiredLabels` should be set to `"*"`

```json
    "matchSpec": {
        "name": "source",
        "action": "regexMatches",
        "value": "^modules\\/.*public_.+bucket$",
        "subMatch": {
          "name": "acl",
          "action": "equals",
          "value": "public-read"
        }
      }
```

```yaml
matchSpec:
  name: source
  action: regexMatches
  value: "^modules\\/.*public_.+bucket$"
  subMatch:
    name: acl
    action: equals
    value: public-read

```

##### isAny
The `isAny` check action passes when the attribute value can be found in the slice passed as the check value. This check action supports strings and numbers

```
"matchSpec" : {
  "name": "acl",
  "action": "isAny",
  "value": ["private", "log-delivery-write"]
}
```

```yaml
matchSpec:
  name: acl
  action: isAny
  value:
  - private
  - log-delivery-write
```

##### isNone
The `isNone` check action passes when the attribute value cannot be found in the slice passed as the check value. This check action supports strings and numbers

```
"matchSpec" : {
  "name": "acl",
  "action": "isNone",
  "value": ["authenticated-read", "public-read"]
}
```

```yaml
matchSpec:
  name: acl
  action: isNone
  value:
  - authenticated-read
  - public-read
```

##### requiresPresence
The `requiresPresence` checks that the resouce in `name` is also present in the Terraform code.

If you wanted to ensure that `aws_vpc_flowlogs` is present if there is a `aws_vpc`, you might use the following `matchSpec`:

```
"matchSpec" : {
  "action": "requiresPresence",
  "name": "aws_vpc_flowlogs"
}
```

```yaml
matchSpec:
  name: aws_vpc_flowlogs
  action: requiresPresence
```

## How do I know my JSON is valid?
We have provided the `tfsec-checkgen` binary which will validate your check file to ensure that it is valid for use with `tfsec`. 

In the future, `tfsec-checkgen` will facilitate the creation of new check files with a wizard approach, for now it can be used to validate your check file.

```shell script
./tfsec-checkgen validate example/custom/.tfsec/custom_checks.json
```


## Are there limitations?
At the moment, check `MatchSpec` is limited in the number of check types it can perform, these are as shown in the previous table.

Custom defined checks also don't come with the comprehensive tests that the built in ones have. This will be addressed in future releases.
