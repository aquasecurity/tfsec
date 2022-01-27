# Contributing

Thank you for considering contributing to tfsec! 

Please consider checking out the following resources:

- [ARCHITECTURE.md](ARCHITECTURE.md): A very high level document that gives an overview of the code and aims to answer the question *Where is the code that does X?*
- [#tfsec on AquaSec Slack](https://slack.aquasec.com): Come and talk over any questions/suggestions you have with us on Slack!
- [tfsec documentation](https://aquasecurity.github.io/tfsec/latest/): General usage documentation and rule information.

## Guide: Adding New Rules

If you have any questions/suggestions about the below, please get in touch! If you get stuck at any point we'd be happy to chat, assist or pair-program with you to get your rule merged.

### Step 1: Fork DefSec

As described in [ARCHITECTURE.md](ARCHITECTURE.md), the rule logic is defined in the [DefSec](https://github.com/aquasecurity/defsec) repository. To add a new rule, we'll need to add it here before pulling it into tfsec. 

So firstly you'll need to [fork the repository](https://github.com/aquasecurity/defsec/fork) and clone it on your local machine:


```bash
# clone your fork of defsec
git clone git@github.com/YOUR_USERNAME/defsec.git
# create a working branch for your new rule
cd defsec && git checkout -b my-awesome-new-rule
```

### Step 2: Add Provider/Service Support

 DefSec already covers most popular cloud providers and many services, resources and attributes available for each of them.

The `provider` package contains structs that represent cloud resources, such as [AWS S3 Buckets](https://github.com/aquasecurity/defsec/blob/master/provider/aws/s3/bucket.go#L5). Rules simply check the various properties of these structs without having to worry about the intricacies of Terraform, CloudFormation or whatever was used to define the resources.

Browse the `provider/` directory to see if your desired provider/service are available. Inside the package for your service, check the defined structs and check that the particular resource (e.g. EC2 Instance) is defined along with the particular attributes you need to check.

If all of the above are already in place, you can skip to *Step 3*. Otherwise, keep reading...

Add structs for your resource(s)/attribute(s)/service/provider as required. These should be accessible via the root [state.State](https://github.com/aquasecurity/defsec/blob/master/state/state.go). If you're adding a brand new provider, you'll need to add a property here. Otherwise just make sure you can access it via the relevant property.

You'll notice that most properties on these structs use things like `types.String` instead of a regular Go `string`. This is because these special types have to store more than the relevant string value - they also contain metadata about where this value was defined - e.g. *The `Name` of this S3 Bucket was defined in main.tf on line 6*. 

We generally refer to these as *wrapped* types, because the actual value is *wrapped* in a struct along with the extra metadata. You don't have to worry about where this metadata comes from right now, `tfsec` will do most of the heavy lifting where this is concerned. You can check out the `types` package or other files in the `provider` package to see what types are available.

You may also spot the inclusion of a `types.Metadata` property in many `provider` structs. This metadata exists to store where the entire resource is defined e.g. *The Terraform block that defines this bucket is on lines 5 to 32 of main.tf*. Again, don't worry about how this will be populated, we'll cover that later.

Another useful thing that metadata provides (on top of the definition file and line range) is whether or not a resource is *managed*. A managed resource in `tfsec` is one which has a `resource` HCL block somewhere in the Terraform code being scanned. Why would we ever have a resource which doesn't exist in the code? Well, sometimes we need to *imply* the existance of resources. For example, if a Terraform template exists which contains the following:

```hcl
resource "aws_s3_bucket_object" "my-file" {
   bucket = "megabucket"
   key    = "backup.zip"
   source = "files/backup.zip"
}
```

An [S3 bucket object](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_object) must live inside a [bucket](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket). It cannot exist without one. But often infrastructure is defined in multiple repositories. The definition for the `megabucket` bucket may exist in another repository. When `tfsec` scans the code above in isolation, it has to *imply* the existance of `megabucket` in order to build the provider hierarchy (`bucket CONTAINS object`). But we don't want to apply all of the security rules to this implied bucket, because it doesn't exist in the source template and we can't be sure of any of it's attributes. `tfsec` flags these implied resources as *unmanaged*, and rule logic will generally avoid checking attributes of these resources for this reason.

### Step 3: Add Rule Logic

Rules are stored in the `rules/*` packages in defsec. They are organised in the same way as the `provider/*` packages.

Each rule should include the following files in the relevant subpackage:

- rule_name.go: The core rule logic and metadata.
- rule_name_test.go: Tests for the rule.

For a rule to be useful, it should include **at least 1** of the following:

- rule_name.tf.go: Good and bad Terraform examples (mainly for documentation purposes)
- rule_name.cf.go: Good and bad CloudFormation examples (mainly for documentation purposes)

If you have examples for other IaC technologies we'd love to add them too! Please let us know on Slack or GitHub.

- create rule files (empty logic)
- describe each field that should be added
- how to assign avd id
- create test
- fail test
- write logic until tests pass
- hooray

```bash
grep -r "AVD-" . | grep AVDID | awk -F'"' '{print $2}' | sort -u
```

At this point you can raise a pull request to defsec, the remaining work just involves `tfsec` ([cfsec](https://github.com/aquasecurity/cfsec) too if you'd like to add CloudFormation support for your rule).

```bash
git add .
git commit -a -m "Add my shiny new rule"
git push
```

### Step 4: Pull the latest defsec into tfsec

- wait until tagged
- pull tag from defsec
- gom vendor

### Step 5: Create/update 


- run e2e tests



- write adapter
- generate docs
- raise pr
- :celebrate:

