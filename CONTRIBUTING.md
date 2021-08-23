# Contributing

Thank you for considering contributing to tfsec! 

We've documented the process of adding a new check below. If you have any other specific questions/problems that are preventing you from raising a PR, please get in touch with us! You can [find us on Slack](https://join.slack.com/t/tfsec/shared_invite/zt-i0vo9rp2-tEizIaT1dS4Eu2hVIsvwDg) - or simply [raise an issue](https://github.com/aquasecurity/tfsec/issues/new) and we'll do our best to help you out.

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

Run `make new-check` to create the stub

Find your new check in `internal/apps/tfsec/rules` and the associated test in `internal/app/tfsec/tests` and complete the check logic

Here's an example:

You need to tell the scanner about your check; this is done by calling an init() function with the following code:

```go
func init() {
	scanner.RegisterCheckRule(rule.Rule{
    
		// the service eg; iam, compute, datalake
		Service: "iam"
        // our new check code
		ID: "gibson-not-hackable",
    
        // all of our documentation data that will be available in the output and/or at https://tfsec.dev/
		Documentation: rule.RuleDocumentation{
			// A description for your check - this message will be output to a user when the check fails.
			Summary:     "The Gibson should not be hackable",
			// A note on the impact associated to the check
			Impact:      "The Gibson might get hacked",
			// A note on the resolution to pass the check
			Resolution:  "Set hackable to false",
			// An explanation for your check. This should contain reasoning why this check enforces good practice. Full markdown is supported here.
			Explanation: `You should always set <code>hackable</code> to *false* to prevent your Gibson from being hacked.`,
			// An example of Terraform code that would fail our check. Our test suite will make sure this example fails the check.
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
		},
        
        	// the provider your check targets
		Provider:       provider.AWSProvider,

        	// which terraform blocks do you want to check - usually "resource"
		RequiredTypes:  []string{"resource"},
        
        	// the type of resource(s) you want to target
		RequiredLabels: []string{"aws_gibson"},
        
        	// the actual logic for your check
		DefaultSeverity: severity.Warning,
		CheckFunc: func(set result.Set, block block.Block, module block.Module) {
			// TODO: add check logic here
		},
	})
}
```

Now all that's left is writing the logic itself. You'll likely find it useful here to learn from preexisting check code, but the logic is usually fairly minimal. Here's a basic example:

```go
...

        DefaultSeverity: severity.Warning,
		CheckFunc: func(set result.Set, block block.Block, module block.Module) {
            if attr := block.GetAttribute("hackable"); attr.IsTrue() {
				set.AddResult().
					WithDescription("The Gibson '%s' is configured to be hackable.", block.Name()).
					WithAttribute(""),
				)
            }
        },
...
```

You can see a good example of a real check file [here](https://github.com/aquasecurity/tfsec/blob/master/internal/app/tfsec/rules/aws001.go).

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