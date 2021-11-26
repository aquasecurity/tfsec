## Ignoring Warnings

You may wish to ignore some warnings. If you'd like to do so, you can
simply add a comment containing `tfsec:ignore:<rule>` to the offending
line in your templates. If the problem refers to a block of code, such
as a multiline string, you can add the comment on the line above the
block, by itself.

For example, to ignore an open security group rule:

```hcl
resource "aws_security_group_rule" "my-rule" {
    type = "ingress"
    cidr_blocks = ["0.0.0.0/0"] #tfsec:ignore:aws-vpc-no-public-ingress-sgr
}
```

...or...

```hcl
resource "aws_security_group_rule" "my-rule" {
    type = "ingress"
    #tfsec:ignore:aws-vpc-no-public-ingress-sgr
    cidr_blocks = ["0.0.0.0/0"]
}
```

If you're not sure which line to add the comment on, just check the
tfsec output for the line number of the discovered problem.

You can ignore multiple rules by concatenating the rules on a single line:

```hcl
#tfsec:ignore:aws-s3-enable-bucket-encryption tfsec:ignore:aws-s3-enable-bucket-logging
resource "aws_s3_bucket" "my-bucket" {
  bucket = "foobar"
  acl    = "private"
}
```

### Expiration Date
You can set expiration date for `ignore` with `yyyy-mm-dd` format. This is a useful feature when you want to ensure ignored issue won't be forgotten and should be revisited in the future.
```
#tfsec:ignore:aws-s3-enable-bucket-encryption:exp:2022-01-02
```
Ignore like this will be active only till `2022-01-02`, after this date it will be deactivated.

### Recent Ignore Changes

As of `v0.52.0`, we fixed an issue where ignores were being incorrectly applied to entire blocks. This has made it more important that ignore comments are added to the correct line(s) in your templates. If tfsec mentions a particular line number as containing an issue you want to ignore, you should add the comment on that same line, or by itself on the line above it (or above the entire block to ignore all issues of that type in the block). If tfsec mentions an entire block as being the issue, you should add a comment on the line above the first line of the block.
