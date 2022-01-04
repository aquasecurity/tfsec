# Contributing

Thank you for considering contributing to tfsec! 

We've documented the process of adding a new check below. If you have any other specific questions/problems that are preventing you from raising a PR, please get in touch with us! You can [find us on Slack](https://join.slack.com/t/tfsec/shared_invite/zt-o6c7mgoj-eJ1sLDv595sKiP5OPoHJww) - or simply [raise an issue](https://github.com/aquasecurity/tfsec/issues/new) and we'll do our best to help you out.

## Adding a New Check

Adding a check typically involves the addition of two files. The first is the file containing the check code itself and it's documentation. The second is a file containing tests for your check. You won't typically need to touch any other files - documentation is generated automatically from the check file itself.

Adding a check can be simplified by running the `make new-check` command. this will request base information about the new check then generate the skeleton code for you to populate.

Key attributes requested;

- Provider: Select the provider from the list
- Short Code: This is a very terse description of the check, it will form the check name
- Summary: A slightly longer free text summary of the check
- Impact: A terse note on the impact associated with the check
- Resolution: A terse note on the resolution in code to pass the check
- Required Types: What kind of blocks is this check for (resource, data, variable etc). Provide this as a space separated list
- Required Label: What kind of labels is this check for (aws_instance, google_container_cluster). Provide this as a space separated list

The generator will determine the next available code and create the check and the check test.

### Determining Severity

We currently use the following list of severities:

| Level    | When to use                                                                        | Example                                               |
| -------- | ---------------------------------------------------------------------------------- | ----------------------------------------------------- |
| Critical | Direct risk of compromise to infrastructure, data or other assets.                 | A database resource is marked as publicly accessible. |
| High     | A misconfiguration that compromises the security of the infrastructure.            | A storage medium is unencrypted.                      |
| Medium   | Best practice has not been followed that impacts the security of the organisation. | "Force destroy" is enabled on a bucket.               |
| Low      | Best practice has not been followed, which decreases operational efficiency.       | Description missing on security group rule.           |


### Writing Your Check Code

Run `make new-check` to start a wizard that will create the new check stub.

Find your new check and the associated test in one of the subfolders of `internal/apps/tfsec/rules` and complete the check logic

Here's an example:

You need to tell the scanner about your check; this is done by calling an `init()` function with the following code:

```go
func init() {
	scanner.RegisterCheckRule(rule.Rule{

        BadExample:  []string{ `
resource "aws_gibson" "my-gibson" {
hackable = true
}
`
        },
        // An example of Terraform code that would pass our check. Our test suite will make sure this example passes the check.
        GoodExample: []string{ `
resource "aws_gibson" "my-gibson" {
hackable = false
}
`
        },
        Links: []string{ // any useful links relating to your check go here
            "https://www.imdb.com/title/tt0113243/"
        },
		// which terraform blocks do you want to check - usually "resource"
		RequiredTypes:  []string{"resource"},
		// the type of resource(s) you want to target
		RequiredLabels: []string{"aws_gibson"},
	})
}
```

Now all that's left is writing the logic itself. This has been moved to [defsec](https://github.com/aquasecurity/defsec). You need to make sure that there's an adapter for the resource. You can see [aws/ec2/adapter.go](https://github.com/aquasecurity/tfsec/blob/master/internal/app/tfsec/adapter/aws/ec2/adapt.go) for an example.

You can see a good example of a real check file [here](https://github.com/aquasecurity/tfsec/blob/master/internal/app/tfsec/rules/aws/vpc/no_public_egress_sg_rule.go).
This check also provides [tests](https://github.com/aquasecurity/tfsec/blob/master/internal/app/tfsec/rules/aws/vpc/no_public_egress_sg_rule_test.go) and uses provided data checks like `cidr.IsAttributeOpen()` provided [here](https://github.com/aquasecurity/tfsec/blob/master/internal/app/tfsec/cidr/cidr.go).

### Writing Tests

There is no longer a need to create dedicated tests for new checks - the `BadExample` and `GoodExample` documentation items on the test will be evaluated during the test runs.

The first example that you add for Good and Bad will be used in the documentation, additional blocks you want to be tested to to verify the check should be added afterwards.

And that's it! If you have any difficulties, please feel free to raise a draft PR and note any questions/problems in the description and we'll do our best to help you out.

### Submitting the PR

When you are ready to submit the PR for review, please run 

```shell
make pr-ready
```

This will run all of the tests, validate for cyclomatic complexity, spelling mistakes and run the end to end tests in the `./example` folder.

Raise your PR when this passes okay (you can expect to see failures from the example run, but overall `make pr-ready` should exit 0)
