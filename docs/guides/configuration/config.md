---
title:  Config File
description:  Config File
summary: Adding an optional config file
author: tfec
tags: [configuration]
---

The tfsec config file can override various tfsec configurations.

The tfsec config file is a file in the `.tfsec` folder in the root check path named `config.json` or `config.yml` and is automatically loaded if it exists.

The config file can also be set with the `--config-file` option:

```
tfsec --config-file tfsec.yml
```

Config files can be downloaded from remote locations using the `--config-file-url`. This must be a HTTP location to a file with either a `json` or `yaml` extension

```
tfsec --config-file-url https://github.com/myorg/tfsecconfig/config.json .
```

## Minimum Severity

You can specify the minimum severity of result that should be reported. By default, every severity is reported. You must use one of CRITICAL, HIGH, MEDIUM, LOW.

```json
{
  "minimum_severity": "MEDIUM"
}
```

or in yaml

```yaml
---
minimum_severity: MEDIUM
```

## Syntax and Overrides

### Severity Overrides

There are occasions where the default severity level for one of the built in checks is too severe or in some cases not strong enough.

The config file can be used to specify overrides for any check identifier to replace the result output.

```json
{
  "severity_overrides": {
    "CUS002": "ERROR",
    "aws-s3-enable-versioning": "LOW"
  }
}
```

or in yaml

```yaml
---
severity_overrides:
  CUS002: ERROR
  aws-s3-enable-versioning: HIGH
```

### Including checks

In some situations you may want to only scan for a subset of the checks - this may be the case if newly added checks need to be evaluated before adding to the CI.
We have removed the option to pass the included checks on the command line but they can be added in the config file.

```json
{
  "include": ["CUS002", "aws-s3-enable-versioning"]
}
```

or in yaml

```yaml
---
include:
  - CUS002
  - aws-s3-enable-versioning
```

### Excluding checks

There are moments where the list of checks you'd want to exclude becomes larger and larger.
Rather than passing all the excluded checks via the command line, you can use the configuration
entry `exclude` to list them all out.

```json
{
  "exclude": ["CUS002", "aws-s3-enable-versioning"]
}
```

or in yaml

```yaml
---
exclude:
  - CUS002
  - aws-s3-enable-versioning
```

Excludes can include an expiry date, after which the check will be re-enabled.

```json
{
  "exclude": ["CUS002:2022-12-31", "aws-s3-enable-versioning"]
}
```

or in yaml


```yaml
---
exclude:
  - CUS002:2022-12-31
  - aws-s3-enable-versioning
```

### Minimum required version

For your CI you might want to pull a config file into all of your build processes with a centrally managed config file. If this is the case, you might also want to require a minimum tfsec version to be used.

This can be achieved in the config file using the `min_required_version` setting. 


```json
{
  "min_required_version": "v1.1.2"
}
```

or in yaml

```yaml
---
min_required_version: v1.1.2
```
