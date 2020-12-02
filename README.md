<p align="center">
  <img width="463" src="./tfsec.png">
</p>

[![Travis Build Status](https://travis-ci.com/tfsec/tfsec.svg?branch=master)](https://travis-ci.com/tfsec/tfsec)
[![GoReportCard](https://goreportcard.com/badge/github.com/tfsec/tfsec)](https://goreportcard.com/report/github.com/tfsec/tfsec)
[![Github Release](https://img.shields.io/github/release/tfsec/tfsec.svg)](https://github.com/tfsec/tfsec/releases)
[![GitHub All Releases](https://img.shields.io/github/downloads/tfsec/tfsec/total)](https://github.com/tfsec/tfsec/releases)
[![Join Our Slack](https://img.shields.io/badge/Slack-Join-green)](https://join.slack.com/t/tfsec/shared_invite/zt-i0vo9rp2-tEizIaT1dS4Eu2hVIsvwDg)

tfsec uses static analysis of your terraform templates to spot potential
security issues. Now with terraform v0.12+ support.

## Example Output

![Example screenshot](screenshot.png)

## Installation

Install with brew/linuxbrew:

```bash
brew install tfsec
```

Install with Chocolatey:

```cmd
choco install tfsec
```

You can also grab the binary for your system from the [releases page](https://github.com/tfsec/tfsec/releases).

Alternatively, install with Go:

```bash
go get -u github.com/tfsec/tfsec/cmd/tfsec
```

## Usage

tfsec will scan the specified directory. If no directory is specified, the current working directory will be used.

The exit status will be non-zero if tfsec finds problems, otherwise the exit status will be zero.

```bash
tfsec .
```

## Use with Docker

As an alternative to installing and running tfsec on your system, you may run tfsec in a Docker container.

To run:

```bash
docker run --rm -it -v "$(pwd):/src" liamg/tfsec /src
```

## Use as GitHub Action

If you want to run tfsec on your repository as a GitHub Action, you can use [https://github.com/triat/terraform-security-scan](https://github.com/triat/terraform-security-scan).

## Features

- Checks for sensitive data inclusion across all providers
- Checks for violations of AWS, Azure and GCP security best practice recommendations
- Scans modules (currently only local modules are supported)
- Evaluates expressions as well as literal values
- Evaluates Terraform functions e.g. `concat()`

## Ignoring Warnings

You may wish to ignore some warnings. If you'd like to do so, you can
simply add a comment containing `tfsec:ignore:<RULE>` to the offending
line in your templates. If the problem refers to a block of code, such
as a multiline string, you can add the comment on the line above the
block, by itself.

For example, to ignore an open security group rule:

```hcl
resource "aws_security_group_rule" "my-rule" {
    type = "ingress"
    cidr_blocks = ["0.0.0.0/0"] #tfsec:ignore:AWS006
}
```

...or...

```hcl
resource "aws_security_group_rule" "my-rule" {
    type = "ingress"
    #tfsec:ignore:AWS006
    cidr_blocks = ["0.0.0.0/0"]
}
```

If you're not sure which line to add the comment on, just check the
tfsec output for the line number of the discovered problem.

You can ignore multiple rules by concatenating the rules on a single line:

```hcl
#tfsec:ignore:AWS017 tfsec:ignore:AWS002
resource "aws_s3_bucket" "my-bucket" {
  bucket = "foobar"
  acl    = "private"
}
```

## Disable checks

You may wish to exclude some checks from running. If you'd like to do so, you can
simply add new argument `-e CHECK1,CHECK2,etc` to your cmd command

```bash
tfsec . -e GEN001,GCP001,GCP002
```

## Including values from .tfvars

You can include values from a tfvars file in the scan,  using, for example: `--tfvars-file terraform.tfvars`.

## Included Checks

Checks are currently limited to AWS/Azure/GCP resources, but
there are also checks which are provider agnostic.

| Checks |
|:---|
|[AWS Checks](https://www.tfsec.dev/docs/aws/home/)|
|[Azure Checks](https://www.tfsec.dev/docs/azure/home/)|
|[GCP Checks](https://www.tfsec.dev/docs/google/home/)|
|[General Checks](https://www.tfsec.dev/docs/general/home/)|

## Running in CI

tfsec is designed for running in a CI pipeline. For this reason it will
exit with a non-zero exit code if a potential problem is detected.
You may wish to run tfsec as part of your build without coloured
output. You can do this using `--no-colour` (or `--no-color` for our
American friends).

## Output options

You can output tfsec results as JSON, CSV, Checkstyle, Sarif, JUnit or just plain old human readable format. Use the `--format` flag
to specify your desired format.

## Github Security Alerts
If you want to integrate with Github Security alerts and include the output of your tfsec checks you can use the [tfsec-sarif-action](https://github.com/marketplace/actions/run-tfsec-with-sarif-upload) Github action to run the static analysis then upload the results to the security alerts tab.

The alerts generated for [tfsec-example-project](https://gighub.com/tfsec/tfsec-github-project) look like this.

![github security alerts](codescanning.png)

When you click through the alerts for the branch, you get more information about the actual issue. 

![github security alerts](scanningalert.png)

For more information about adding security alerts, check 

## Support for older terraform versions

If you need to support versions of terraform which use HCL v1
(terraform <0.12), you can use `v0.1.3` of tfsec, though support is
very limited and has fewer checks.
