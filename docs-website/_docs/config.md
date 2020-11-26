---
title: Config
permalink: /docs/config/
---

## Severity Overrides

There are occasions where the default severity level for one of the built in checks is too severe or in some cases not strong enough. 

The config file can be used to specify overrides for any check identifier to replace the result output.

The structure of the config file can be either `json` or `yaml` and is passed using the `--config-file` argument at runtime.

```json
{
  "severity_overrides": {
    "CUS002": "ERROR",
    "AWS025": "WARNING"
  }
}
``` 

or 
```yaml
---
severity_overrides:
  CUS002: ERROR
  AWS025: INFO
```

## Running with the config

To run tfsec against a Terraform folder called `tf` with the config file `tfsec.yml` you would run 

```shell script
tfsec --config-file tfsec.yml ./tf
```
