---
title: Rego Policies
description: Rego Policies
subtitle: Writing Rego Policies
description: Writing Rego Policies
author: tfsec
tags: [rego, custom, code scanning, security analysis]
---

_tfsec_ has the capability to apply user-defined [Rego](https://www.openpolicyagent.org/docs/latest/policy-language/) policies.

This is a useful feature if your organisation needs to implement custom security policies on top of avoid other misconfigurations and enforcing best practice guidelines.

## Example Policy

```rego
package custom.aws.s3.no_insecure_buckets

import data.lib.result

deny[res] {
    bucket := input.aws.s3.buckets[_]
    bucket.name.value == "insecure-bucket"
    msg := "Bucket name should not be 'insecure-bucket'"
    res := result.new(msg, bucket.name)
}
```

Let's break this down.

The _package_ (line #1) must always start with the `custom` namespace in order for _tfsec_ to recognise it. The rest of the package name can be whatever you like, but it's generally a good idea to break things down by cloud provider, service, environment etc.

The name of the `deny` rule is important. Rule names must either be `deny`, or begin with `deny_` in order to highlight an issue when _tfsec_ runs.

The `input` variable contains cloud resources organised by provider (e.g _aws_), and then service (e.g. _s3_). You can see what this looks like by running _tfsec_ on your project with the `--print-rego-input` flag. Combining this with the [jq](https://stedolan.github.io/jq/) tool is very helpful:

```console
tfsec --print-rego-input | jq '.aws.s3.buckets[0].name'
{
  "endline": 3,
  "explicit": true,
  "filepath": "/home/liamg/rego-playground/terraform/bucket.tf",
  "managed": true,
  "startline": 3,
  "value": "secure-bucket"
}
```

For more information about the input structure, you can review the entire schema in code form by studying the `state.State` Go struct [defined in the defsec source code](https://github.com/aquasecurity/defsec/blob/master/state/state.go#L18-L28). All property names are converted to lower-case for consistency, to make writing policies easier.

You may have noticed that the policy checks `bucket.name.value`, instead of just `bucket.name`. This is because the `bucket.name` property contains more than just the _value_ of the property, it also contains various metadata about where this property value was defined, including the filename and line number of the source Terraform file. You can see an example of this metadata in the jq output above.

The `res` object which is returned should be created with the `result.new()` function. This is the magic that ensures line numbers and file numbers can be reported when a policy fails. The function takes two parameters:

- _msg_ This parameter is a string which explains the specific issue which has been encountered, e.g. `MFA is not enabled for this user`
- _source_ This parameter is the property or object where the problem was encountered.

If you are writing a policy which has no meaningful _source_ parameter/object, you can return a simple string from the rule instead.

## Applying Rego Policies

You can ask _tfsec_ to apply your custom Rego policies by using the `--rego-policy-dir` flag to specify the directory containing your policies. 

Policies will be loaded recursively starting at this directory, and so can be organised using nested subdirectories if desired.

If this flag is not specified, no local directories will be scanned for rego policies.
