# Contributing

Thank you for considering contributing to tfsec! 

We've documented the process of adding a new check below. If you have any other specific questions/problems that are preventing you from raising a PR, please get in touch with us! You can [find us on Slack](https://join.slack.com/t/tfsec/shared_invite/zt-i0vo9rp2-tEizIaT1dS4Eu2hVIsvwDg) - or simply [raise an issue](https://github.com/tfsec/tfsec/issues/new) and we'll do our best to help you out.

## Adding a New Check

Adding a check typically involves the addition of two files. The first is the file containing the check code itself and it's documentation. The second is a file containing tests for your check. You won't typically need to touch any other files - documentation is generated automatically from the check file itself.

Adding a check can be simplified by running the `make new-check` command. this will request base information about the new check then generate the skeleton code for you to populate.

Key attributes requested;

- Provider: Select the provider from the list
- Short Code: This is a very terse description of the check, it will form the check name
- Summary: A slightly longer free text summary of the check
- Required Types: What kind of blocks is this check for (resource, data, variable etc). Provide this as a space separated list
- Required Label: What kind of labels is this check for (aws_instance, google_container_cluster). Provide this as a space separated list

The generator will determine the next available code and create the check and the check test.

### Writing Your Check Code

First you'll need to generate a `Rule Code` for your check. This is prefixed with 3 characters describing the provider for your check, so for AWS resources, it would begin with `AWS`. You've probably guessed that if the "highest" check rule ID for the provider is `AWS122` on the master branch, your check code should be `AWS123`. If your check will target multiple providers, you can prefix it with `GEN`.

You can now create your check file in `./internal/app/tfsec/checks/`.

You'll need to set up some constants that explain what your check is for and give some code examples. The constants should be named in a way that generally describes your check functionality. 

Here's an example:

```go
// The rule code for your check
const AWSGibsonHackableCode scanner.RuleCode = "AWS123"

// A description for your check - this message will be output to a user when the check fails.
const AWSGibsonHackableDescription scanner.RuleSummary = "The Gibson should not be hackable"

// An explanation for your check. This should contain reasoning why this check enforces good practice. Full markdown is supported here.
const AWSGibsonHackableExplanation = `
You should always set <code>hackable</code> to *false* to prevent your Gibson from being hacked.
`

// An example of Terraform code that would fail our check. Our test suite will make sure this example fails the check.
const AWSGibsonHackableBadExample = `
resource "aws_gibson" "my-gibson" {
    hackable = true
}
`

// An example of Terraform code that would pass our check. Our test suite will make sure this example passes the check.
const AWSGibsonHackableGoodExample = `
resource "aws_gibson" "my-gibson" {
    hackable = false
}
`
```

Next up, you need to tell the scanner about your check. You can do this by calling an init() function with the following code:

```go
func init() {
	scanner.RegisterCheck(scanner.Check{
    
        	// our new check code
		Code: AWSGibsonHackableCode,
    
        	// all of our documentation data that will be available in the output and/or at https://tfsec.dev/
		Documentation: scanner.CheckDocumentation{
			Summary:     AWSGibsonHackableDescription,
			Explanation: AWSGibsonHackableExplanation,
			BadExample:  AWSGibsonHackableBadExample,
			GoodExample: AWSGibsonHackableGoodExample,
			Links: []string{ // any useful links relating to your check go here
                		"https://www.imdb.com/title/tt0113243/"
			},
		},
        
        	// the provider your check targets
		Provider:       scanner.AWSProvider,

        	// which terraform blocks do you want to check - usually "resource"
		RequiredTypes:  []string{"resource"},
        
        	// the type of resource(s) you want to target
		RequiredLabels: []string{"aws_gibson"},
        
        	// the actual logic for your check
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {
            		// TODO: add check logic here
			return nil
		},
	})
}
```

Now all that's left is writing the logic itself. You'll likely find it useful here to learn from preexisting check code, but the logic is usually fairly minimal. Here's a basic example:

```go
...

        CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {

            if attr := block.GetAttribute("hackable"); attr != nil && attr.Value().Type() == cty.Bool {
                if attr.Value().True() {
                    return []scanner.Result{
                        check.NewResultWithValueAnnotation(
                            fmt.Sprintf("The Gibson '%s' is configured to be hackable.", block.Name()),
                            attr.Range(),
                            attr,
                            scanner.SeverityWarning,
                        ),
                    }
                }
            }
        },
...
```

You can see a good example of a real check file [here](https://github.com/tfsec/tfsec/blob/master/internal/app/tfsec/checks/aws001.go).

### Writing Tests

It's also a requirement for new checks to include tests.

You can add a test file in `./internal/app/tfsec/test`. The basic layout is as follows:

```go
package test

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/checks"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

func Test_AWSGibsonHackable(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode scanner.RuleCode
		mustExcludeResultCode scanner.RuleCode
	}{
		// this makes sure the check works in the most basic scenario
		{
			name: "check fails when hackable is set to true on an aws_gibson resource",
			source: `
resource "aws_gibson" "my-gibson" {
	hackable = true
}`,
			mustIncludeResultCode: checks.AWSGibsonHackableCode,
       		},
		// this checks for a false positive
		{ 
			name: "check passes when hackable is set to false on an aws_gibson resource",
			source: `
resource "aws_gibson" "my-gibson" {
	hackable = false
}`,
			mustExcludeResultCode: checks.AWSGibsonHackableCode,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
```

And that's it! If you have any difficulties, please feel free to raise a draft PR and note any questions/problems in the description and we'll do our best to help you out.
