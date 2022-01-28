# Architecture

This document aims to answer the question *Where is the code that does X?*

For more information please check out our [contributing guide](CONTRIBUTING.md) or get in touch with us via Slack/issues/discussions.

## Important Packages

At a very high level, tfsec is structured like this. The most important packages are broken down below.

```
    *.tf files -> parser.Parse() -> adapter.Adapt() -> scanner.Scan() -> Results
```

### `cmd/tfsec`

The entry point for the main *tfsec* CLI.

### `internal/app/tfsec/cmd`

Code to support running in the CLI, including flags, output settings etc.

### `internal/pkg/parser`

Takes plaintext Terraform HCL templates as input and produces logical abstractions from the `internal/pkg/block` package. Returns a slice of *modules* which in turn contain blocks which can contain other blocks, which can in turn ultimately contain attributes, as is the HCL format. Each of the abstractions for these concepts has many utility methods.

### `internal/pkg/adapter`

Takes the abstracted Terraform building blocks mentioned above e.g. *blocks*, *resources*, *attributes* etc. as input and *adapts* them into a common data format which represents cloud resource e.g. a struct which represents an AWS S3 bucket.

### `internal/pkg/scanner`

Takes the *adapted* cloud resources as input and runs all defsec rules against them. Returns a list of results as output.

### `test`

End-to-end tests that pull example Terraform code from defsec, run it through `tfsec` and apply all defsec rules, ensuring the expected result for each code example.

