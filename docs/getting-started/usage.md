---
title: Usage
description: Usage
subtitle: Using tfsec
description: Using tfsec
author: tfsec
tags: [installation, quickstart]
---

tfsec can by run with no arguments and will act on the current folder. 

For a richer experience, there are many additional command line arguments that you can make use of.


| Argument                                                 | Short Code | Description                                                                              |
| :------------------------------------------------------- | :--------- | :--------------------------------------------------------------------------------------- |
| `--allow-checks-to-panic`                                | `-p`       | Allow panics to propagate up from rule checking                                          |
| `--concise-output`                                       |            | Reduce the amount of output and no statistics                                            |
| `--config-file [path to config file]`                    |            | Config file to use during run                                                            |
| `--custom-check-dir [path to checks dir]`                |            | Explicitly the custom checks dir location                                                |
| `--debug`                                                |            | Enable verbose logging, same as `--verbose` but for people who prefer to say debug       |
| `--detailed-exit-code`                                   |            | Produce more detailed exit status codes.                                                 |
| `--exclude [comma,separated,rule,ids]`                   | `-e`       | Provide comma-separated list of rule IDs to exclude from run.                            |
| `--exclude-path strings`                                 |            | Path to exclude from parser, can be used multiple times                                  |
| `--exclude-downloaded-modules`                           |            | Remove results for downloaded modules in .terraform folder                               |
| `--filter-results [comma,separated,riles,to,check]`      |            | Filter results to return specific checks only (supports comma-delimited input).          |
| `--force-all-dirs`                                       |            | Don't search for tf files, include everything below provided directory.                  |
| `--format [default,json,csv,checkstyle,junit,sarif,gif]` | `-f`       | Select output format: default, json, csv, checkstyle, junit, sarif                       |
| `--help`                                                 | `-h`       | help for tfsec                                                                           |
| `--ignore-hcl-errors`                                    |            | Stop and report an error if an HCL parse error is encountered                            |
| `--include-ignored`                                      |            | Ignore comments with have no effect and all resources will be scanned                    |
| `--include-passed`                                       |            | Resources that pass checks are included in the result output                             |
| `--migrate-ignores`                                      |            | Migrate ignore codes to the new ID structure eg; AWS077 to aws-s3-enable-versioning      |
| `--no-color`                                             |            | Disable colored output (American style!)                                                 |
| `--no-colour`                                            |            | Disable coloured output                                                                  |
| `--out [filepath to output to]`                          |            | Set output file                                                                          |
| `--run-statistics`                                       |            | View statistics table of current findings.                                               |
| `--soft-fail`                                            | `-s`       | Runs checks but suppresses error code                                                    |
| `--sort-severity`                                        |            | Sort the results by severity from highest to lowest                                      |
| `--tfvars-file strings`                                  |            | Path to .tfvars file, can be used multiple times and evaluated in order of specification |
| `--update`                                               |            | Update to latest version                                                                 |
| `--verbose`                                              |            | Enable verbose logging                                                                   |
| `--version`                                              | `-v`       | Show version information and exit                                                        |
| `--workspace [terraform workspace]`                      | `-w`       | Specify a workspace for ignore limits                                                    |

This list can also be found by running `tfsec --help`
