# Contributing

Thank you for considering a contribution to tfsec! :heart:

<p align="center">
    <img alt="welcome to the party, pal!" src="https://media.giphy.com/media/l0MYGb1LuZ3n7dRnO/giphy.gif"/>
</p>

Please review the following resources:

- [ARCHITECTURE.md](ARCHITECTURE.md): A very high level document that gives an overview of the code and aims to answer the question *Where is the code that does X?*
- [#tfsec on AquaSec Slack](https://slack.aquasec.com): Come and talk over any questions/suggestions you have with us on Slack!
- [tfsec documentation](https://aquasecurity.github.io/tfsec/latest/): General usage documentation and rule information.

## :ballot_box_with_check: PR Checklist

- Ensure the build passes locally first with `make pr-ready`.
- Add a brief description of your change.
- Link to the issue which the PR resolves. Please [create one](https://github.com/aquasecurity/tfsec/issues/new/choose) if necessary.
- Prefix your PR title with one of feat, fix, docs, style, refactor, perf, test, build, ci, chore, revert ([see here](https://github.com/commitizen/conventional-commit-types/blob/v3.0.0/index.json)) as described in [Conventional Commits](https://www.conventionalcommits.org/) e.g. `feat: Add new rule for AWS S3 bucket encryption`.
- For bonus points, include a gif to maintain reviewer morale.
    

## :book: Guide: Adding New Rules 

If you have any questions/suggestions about the steps below, please get in touch! If you get stuck at any point we'd be happy to chat, assist or pair-program with you to get your rule merged. The process may look daunting, however, many steps can often be skipped or are simpler than the volume of text makes them look at first glance. 
Don't be afraid to get stuck in and ask us for help if required! For quick assistance [Slack](https://slack.aquasec.com) is often the quickest route to help.

### :fork_and_knife: Step 1: Fork *defsec*

As described in [ARCHITECTURE.md](ARCHITECTURE.md), the rule logic is defined in the [DefSec](https://github.com/aquasecurity/defsec) repository. To add a new rule, we'll need to add it here before pulling it into tfsec. 

So firstly you'll need to [fork the repository](https://github.com/aquasecurity/defsec/fork) and clone it on your local machine:

```bash
# clone your fork of defsec
git clone git@github.com/YOUR_USERNAME/defsec.git
# create a working branch for your new rule
cd defsec 
git checkout -b my-awesome-new-rule
```

### :cloud: Step 2: Add Cloud Provider/Service Support

 DefSec already covers most popular cloud providers; with many services, resources and attributes available for each.

The `provider` package contains structs that represent cloud resources, such as [AWS S3 Buckets](https://github.com/aquasecurity/defsec/blob/master/provider/aws/s3/bucket.go#L5). Rules simply check the various properties of these structs without having to worry about the intricacies of Terraform, CloudFormation or whatever was used to define the resources.

Browse the `provider/` directory to see if your desired provider/service are available. Inside the package for your service, check the defined structs and check that the particular resource (e.g. EC2 Instance) is defined along with the particular attributes you need to check.

If all of the above are already in place, you can skip to *Step 3*. Otherwise, keep reading...

<p align="center">
    <img alt="Leaky cloud" src="https://media.giphy.com/media/mNG0rIdAYvLog0Wr8H/giphy.gif" />
</p>

Add structs for your resource(s)/attribute(s)/service/provider as required. These should be accessible via the root [state.State](https://github.com/aquasecurity/defsec/blob/master/state/state.go). If you're adding a brand new provider, you'll need to add a property here. Otherwise just make sure you can access it via the relevant property.

You'll notice that most properties on these structs use things like `types.String` instead of a regular Go `string`. This is because these special types have to store more than the relevant string value - they also contain metadata about where this value was defined - e.g. *The `Name` of this S3 Bucket was defined in main.tf on line 6*. 

We generally refer to these as *wrapped* types, because the actual value is *wrapped* in a struct along with the extra metadata. You don't have to worry about where this metadata comes from right now, `tfsec` will do most of the heavy lifting where this is concerned. You can check out the `types` package or other files in the `provider` package to see what types are available.

You may also spot the inclusion of a `types.Metadata` property in many `provider` structs. This metadata exists to store where the entire resource is defined e.g. *The Terraform block that defines this bucket is on lines 5 to 32 of main.tf*. Again, don't worry about how this will be populated, we'll cover that later.

Another useful thing that metadata provides (on top of the definition file and line range) is whether or not a resource is *managed*. A managed resource in `tfsec` is one which has a `resource` HCL block somewhere in the Terraform code being scanned. Why would we ever have a resource which doesn't exist in the code? Well, sometimes we need to *imply* the existence of resources. For example, if a Terraform template exists which contains the following:

```hcl
resource "aws_s3_bucket_object" "my-file" {
   bucket = "megabucket"
   key    = "backup.zip"
   source = "files/backup.zip"
}
```

An [S3 bucket object](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_object) must live inside a [bucket](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket). It cannot exist without one. But often infrastructure is defined in multiple repositories. The definition for the `megabucket` bucket may exist in another repository. When `tfsec` scans the code above in isolation, it has to *imply* the existence of `megabucket` in order to build the provider hierarchy (`bucket CONTAINS object`). But we don't want to apply all of the security rules to this implied bucket, because it doesn't exist in the source template and we can't be sure of any of it's attributes. `tfsec` flags these implied resources as *unmanaged*, and rule logic will generally avoid checking attributes of these resources for this reason.

### :lock: Step 3: Add Rule Logic

Rules are stored in the `rules/*` packages in defsec. They are organised in the same way as the `provider/*` packages: grouped together by provider and then service. Different resources are generally broken out into separate files, but this is left to the judgement of the developer.

Each rule should include the following files:

- rule_name.go: The core rule logic and metadata.
- rule_name_test.go: Tests for the rule.

For a rule to be useful, it should include **at least 1** of the following:

- rule_name.tf.go: Good and bad Terraform examples (mainly for documentation purposes)
- rule_name.cf.go: Good and bad CloudFormation examples (mainly for documentation purposes)

If you have examples for other IaC technologies we'd love to add them too! Please let us know on Slack or GitHub.


<p align="center">
    <img alt="You have to live by my rules" src="https://media.giphy.com/media/ZXffEBBmsI3md367PN/giphy.gif" />
</p>

Create your core rule file by duplicating an existing rule and renaming it appropriately. Remove all logic from the function at the end for now.

Rules should add results for failure or non-compliance with the check logic AND also provide a Passed result for when the check complies.

Fill out the `rules.Rule` struct with appropriate information. The fields are described below:

| Field            | Description |
| ---------------- | ----------- |
| AVDID            | This is a unique ID that identifies the rule not just within DefSec, but within the [AVD](https://avd.aquasec.com/). The ID is composed of the prefix `AVD-`, three letters representing the provider in capitals e.g. `AWS`, another `-`, and then a 4-digit, zero-padded number. For example: `AVD-AWS-0086`. The easiest way to assign a new AVD ID is to run `grep -r "AVD-" . | grep AVDID | awk -F'"' '{print $2}' | sort -u` to find the highest number for your provider and increment it by one.
| Provider         | You can set this using a constant from the `provider` package, listed [here](https://github.com/aquasecurity/defsec/blob/master/provider/providers.go#L8-L21)
| Service          | A string representing the service your rule relates to (lower-case), e.g. `s3`. This will generally match the package your rule is inside.
| ShortCode        | This is a human-readable identifier for your check that uniquely describes it within the provider and service. e.g. `block-public-acls`
| Summary          | A short paragraph that summarises what best-practice the rule is trying to enforce. e.g. *Data stored in service X should be encrypted at rest*
| Impact           | A short sentence describing the security impact of the rule failing e.g. *All data stored using service Y will be publicly available*.
| Resolution       | A short sentence describing how to resolve the issue. This shouldn't be tied to implementation technology such as Terraform/CloudFormation, but written at a higher level in terms of Cloud Resources and configuration e.g. *Enable encryption for this bucket*
| Explanation      | A detailed explanation of why this is an issue. Often very short for simple rules.
| Links            | A list of external references/guides that relate to the rule.
| Severity         | The severity of the check.
| Terraform/CloudFormation | These contain good and bad code examples (those that pass and fail the rule respectively); a list of IaC technology specific links e.g. a link to the specific resource documentation on the [Terraform Registry](https://registry.terraform.io/); and a markdown block that describes remediation using the specific IaC technology e.g. *Set the Terraform parameter `enable_encryption` to `true`*

We use the following guide to approximate severity:

| Level    | When to use                                                                        | Example                                               |
| -------- | ---------------------------------------------------------------------------------- | ----------------------------------------------------- |
| Critical | Direct risk of compromise to infrastructure, data or other assets.                 | A database resource is marked as publicly accessible. |
| High     | A misconfiguration that indirectly compromises the security of the infrastructure.            | A storage medium is unencrypted.                      |
| Medium   | Best practice has not been followed that impacts the security posture of the organisation. | "Force destroy" is enabled on a bucket.               |
| Low      | Best practice has not been followed, which decreases operational efficiency.       | Description missing on security group rule.           |

Next up, it's time to write some tests. You can copy the [Google BigQuery tests](https://github.com/aquasecurity/defsec/blob/master/rules/google/bigquery/no_public_access_test.go) as a starting point. 

The tests should take a provider *service* struct as an input, apply the rule, and check that the rule had a positive/negative result as required.

Running the tests should fail, as there is currently no logic in the rule. Now it's finally time to write your rule logic! This lives in the function at the end of your core rule file. 

The `*state.State` which is passed to the rule contains all cloud resources which have been detected in Terraform templates by `tfsec` (or in another set of sources by another tool!). Most rules will look in this struct for certain cloud resources and check certain properties, they're relatively simple and you can find inspiration in any of the existing rules. If you find a positive result, you can use `results.Add(...)` to record it. This method takes a description of the issue e.g. *Bucket is not encrypted* and the *source* of the issue. The source is either the struct that represents the cloud resource with the issue, or preferably a specific attribute of the struct, where possible. This is recorded so the source of the issue can be shown to the end user when tfsec runs.

### :left_right_arrow: Step 4: Write an Adapter

*defsec* (and therefore *tfsec*) supports a lot of cloud providers and services, but there are always more to add (especially with the frequency that AWS adds new services!) and so it is often required to add or update *adapters*. *defsec* parses Terraform templates into handy Go structs that represent HCL concepts such as *blocks*, *attributes* etc. and also Terraform specific concepts such as *modules*, *resources* etc. 

All of the structs that describe a Terraform project are passed to the *adapters* to summarise into *defsec* structs - those that you created in *Step 2* above.

<p align="center">
    <img alt="the squirrel needs to adapt?" src="https://media.giphy.com/media/a1zcR7A6v5k9Mcdxuz/giphy.gif" />
</p>

Your adapter will receive a list of Terraform modules which you can traverse to find particular blocks, attributes etc., and manufacture a series of defsec structs to return. You can see how this works by reviewing some of the many existing implementations.

Whilst the end-to-end tests will automatically cover your new rule and adapter, it's recommended to also add a more granular set of tests for your adaptation code. You can [check out some examples of this](https://github.com/aquasecurity/defsec/tree/master/adapters/terraform/aws/apigateway) to get some inspiration. Or some copy and paste fuel.

### Step 5: Create your *defsec* Pull Request 

Once your tests pass, it's time to [raise a pull request](https://github.com/aquasecurity/defsec/compare)!

You can see a good example of a PR for a new defsec rule [here](https://github.com/aquasecurity/defsec/pull/115/files).

At this point you're waiting on us to review and merge your pull request. We're aiming to get to all pull requests within days in the post version 1 world, but often much faster - you can often chat to us on Slack to accelerate the process.

While waiting you can [fork the tfsec repository](https://github.com/aquasecurity/tfsec/fork) and clone it on your local machine to prepare for the next step:

```bash
# clone your fork of tfsec
git clone git@github.com/YOUR_USERNAME/tfsec.git
# create a working branch for your new rule
cd tfsec && git checkout -b my-awesome-new-rule
```

After merging a defsec PR we'll create a tag straight away - we generally release little and often - so you can use the new version in tfsec.

### :arrow_down: Step 6: Apply the New Rule in *tfsec*

> NOTE: If you'd like to earn bonus points and support running your rule against *CloudFormation*, you can repeat this step in the [cfsec](https://github.com/aquasecurity/cfsec) repository - if not we'll get to it eventually and make sure your rule runs everywhere!

Update the version of defsec that is used by tfsec:

```bash
# in your tfsec repo directory
go get github.com/aquasecurity/defsec@latest
go mod vendor
```

At this point *tfsec* will automatically pull in your new rule when it runs. It will also pull in the good/bad example code you provided earlier and automatically test this code to see if the rule matches expectations against each.

If you run `make test` and everything looks good, you can skip to *Step 6* - you're ready to raise a pull request against *tfsec* and put your feet up. 

Alternatively, if the tests fail, it's likely that *tfsec* needs to be taught how to recognise the cloud resource your test covers in Terraform code, and translate it to a defsec struct. We refer to this process as *adaptation*.


### :checkered_flag: Step 7: Prepare a *tfsec* Pull Request

<p align="center">
    <img alt="Pull!" src="https://media.giphy.com/media/nJKDTpuxnZE7fb6Z1b/giphy.gif" />
</p>

In order to raise your *tfsec* pull request, please run:

```bash
make publish-docs
```

This will automatically create markdown documentation for your new rule and add it to the documentation navigation etc. You'll need to commit these documentation changes.

```bash
make pr-ready
```

This will run some linters, run the tests and replicate the checks we apply in CI so you can ensure the build passes locally before pushing your code.

Now you're ready to [raise the pull request](https://github.com/aquasecurity/tfsec/compare). We'll try to review it as soon as possible, but if it's taking longer than you'd like, feel free to chat to us on Slack.

### :partying_face: Step 7: Relax

You've earned it. You have helped countless individuals and organisations to secure their infrastructure and make the internet a safer place!

<p align="center">
    <img alt="relaxing cat" src="https://i.giphy.com/media/d7nd6bdypnYjGT1jP3/giphy.webp"/>
</p>
