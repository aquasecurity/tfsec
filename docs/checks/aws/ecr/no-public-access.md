---
title: no-public-access
---

### Explanation

Allowing public access to the ECR repository risks leaking sensitive of abusable information

### Possible Impact
Risk of potential data leakage of sensitive artifacts

### Suggested Resolution
Do not allow public access in the policy


### Insecure Example

The following example will fail the aws-ecr-no-public-access check.

```terraform

resource "aws_ecr_repository" "foo" {
  name = "bar"
}

resource "aws_ecr_repository_policy" "foopolicy" {
  repository = aws_ecr_repository.foo.name

  policy = <<EOF
{
    "Version": "2008-10-17",
    "Statement": [
        {
            "Sid": "new policy",
            "Effect": "Allow",
            "Principal": "*",
            "Action": [
                "ecr:GetDownloadUrlForLayer",
                "ecr:BatchGetImage",
                "ecr:BatchCheckLayerAvailability",
                "ecr:PutImage",
                "ecr:InitiateLayerUpload",
                "ecr:UploadLayerPart",
                "ecr:CompleteLayerUpload",
                "ecr:DescribeRepositories",
                "ecr:GetRepositoryPolicy",
                "ecr:ListImages",
                "ecr:DeleteRepository",
                "ecr:BatchDeleteImage",
                "ecr:SetRepositoryPolicy",
                "ecr:DeleteRepositoryPolicy"
            ]
        }
    ]
}
EOF
}

```



### Secure Example

The following example will pass the aws-ecr-no-public-access check.

```terraform

resource "aws_ecr_repository" "foo" {
  name = "bar"
}

resource "aws_ecr_repository_policy" "foopolicy" {
  repository = aws_ecr_repository.foo.name

  policy = <<EOF
{
    "Version": "2008-10-17",
    "Statement": [
        {
            "Sid": "new policy",
            "Effect": "Allow",
            "Principal": "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root",
            "Action": [
                "ecr:GetDownloadUrlForLayer",
                "ecr:BatchGetImage",
                "ecr:BatchCheckLayerAvailability",
                "ecr:PutImage",
                "ecr:InitiateLayerUpload",
                "ecr:UploadLayerPart",
                "ecr:CompleteLayerUpload",
                "ecr:DescribeRepositories",
                "ecr:GetRepositoryPolicy",
                "ecr:ListImages",
                "ecr:DeleteRepository",
                "ecr:BatchDeleteImage",
                "ecr:SetRepositoryPolicy",
                "ecr:DeleteRepositoryPolicy"
            ]
        }
    ]
}
EOF
}

```




### Related Links


- [https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecr_repository_policy#policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecr_repository_policy#policy){:target="_blank" rel="nofollow noreferrer noopener"}


