---
title: Custom Checks Library
permalink: /docs/check_library/custom_check_library/
---

The addition of [custom checks](/docs/custom_checks/) to tfsec means you can quickly add your own company specifc security and compliance checks. 

Custom checks are created as json files with the filename suffix of `_tfsec.json` in the `.tfsec` directory in the root of the folder being evaluated.

Checks sit in the `checks` array of the json file.

```json
{
  "checks": [
        ...
    ]
}
```

More checks will be added to the library - please feel free to create new checks and submit them as issues to the [tfsec project](https://github.com/tfsec/tfsec/issues)

|Check|Description|
|:----|:----------|
|[tag checking](/docs/check_library/tagged)|Check that required tags are present on specific resources |
|[in module checking](/docs/check_library/in_module)|Check that the resource being created is a component of a module|
|[acl checking](/docs/check_library/acls)|Check that acl value is not one of the prohibited values|