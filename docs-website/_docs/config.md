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

## Excluding checks

There are moments where the list of checks you'd want to exclude becomes larger and larger.
Rather than passing all the excluded checks via the command line, you can use the configuration
entry `exclude` to list them all out. 

```json
{
  "exclude": ["CUS002", "AWS025"]
}
``` 

or 

```yaml
---
exclude:
  - CUS002
  - AWS025
```

## Running with the config

To run tfsec against a Terraform folder called `tf` with the config file `tfsec.yml` you would run 

```
tfsec --config-file tfsec.yml ./tf
```
