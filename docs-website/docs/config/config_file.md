---
title: Config - Config File
permalink: /docs/config_file/
parent: Config
---

## Config File

The tfsec config file can override various tfsec configurations.

The tfsec config file is a file in the `.tfsec` folder in the root check path named `config.json` or `config.yml` and is automaticaly loaded if it exists.

The config file can also be set with the `--config-file` option:

```
tfsec --config-file tfsec.yml
```

## Syntax and Overrides

### Severity Overrides

There are occasions where the default severity level for one of the built in checks is too severe or in some cases not strong enough.

The config file can be used to specify overrides for any check identifier to replace the result output.

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

### Excluding checks

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
