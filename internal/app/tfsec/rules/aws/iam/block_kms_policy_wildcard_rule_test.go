package iam

// generator-locked
import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
)

func Test_AWSKMSManagedPoliciesShouldNotAllowDecryptionActionsOnAllKMSKeys(t *testing.T) {
	expectedCode := "aws-iam-block-kms-policy-wildcard"

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "outright '*' in policy that contains KMS actions",
			source: `
				resource "aws_iam_role_policy" "test_policy" {
				  name = "test_policy"
				  role = aws_iam_role.test_role.id

				  # Terraform's "jsonencode" function converts a
				  # Terraform expression result to valid JSON syntax.
				  policy = data.aws_iam_policy_document.kms_policy.json
				}

				resource "aws_iam_role" "test_role" {
				  name = "test_role"
				  assume_role_policy = jsonencode({
				    Version = "2012-10-17"
				    Statement = [
				      {
				        Action = "sts:AssumeRole"
				        Effect = "Allow"
				        Sid    = ""
				        Principal = {
				          Service = "ec2.amazonaws.com"
				        }
				      },
				    ]
				  })
				}

				data "aws_iam_policy_document" "kms_policy" {
				  statement {
				    principals {
				      type        = "AWS"
				      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
				    }
				    actions   = ["kms:*"]
				    resources = ["*"]
				  }
				}
				`,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "partial key and alias arn with asterisk in them",
			source: `
		resource "aws_iam_role_policy" "test_policy" {
		  name = "test_policy"
		  role = aws_iam_role.test_role.id

		  # Terraform's "jsonencode" function converts a
		  # Terraform expression result to valid JSON syntax.
		  policy = data.aws_iam_policy_document.kms_policy.json
		}

		resource "aws_iam_role" "test_role" {
		  name = "test_role"
		  assume_role_policy = jsonencode({
		    Version = "2012-10-17"
		    Statement = [
		      {
		        Action = "sts:AssumeRole"
		        Effect = "Allow"
		        Sid    = ""
		        Principal = {
		          Service = "ec2.amazonaws.com"
		        }
		      },
		    ]
		  })
		}

		data "aws_iam_policy_document" "kms_policy" {
		  statement {
		    principals {
		      type        = "AWS"
		      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
		    }
		    actions   = ["kms:*"]
		    resources = [
		      "arn:aws:kms:*:*:alias/*",
		      "arn:aws:kms:*:*:key/*",
		    ]
		  }
		}
		`,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "partial key and alias arn with asterisk in them",
			source: `
		resource "aws_iam_role_policy" "test_policy" {
		  name = "test_policy"
		  role = aws_iam_role.test_role.id

		  # Terraform's "jsonencode" function converts a
		  # Terraform expression result to valid JSON syntax.
		  policy = data.aws_iam_policy_document.kms_policy.json
		}

		resource "aws_iam_role" "test_role" {
		  name = "test_role"
		  assume_role_policy = jsonencode({
		    Version = "2012-10-17"
		    Statement = [
		      {
		        Action = "sts:AssumeRole"
		        Effect = "Allow"
		        Sid    = ""
		        Principal = {
		          Service = "ec2.amazonaws.com"
		        }
		      },
		    ]
		  })
		}

		data "aws_iam_policy_document" "kms_policy" {
		  statement {
		    principals {
		      type        = "AWS"
		      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
		    }
		    actions   = ["kms:*"]
		    resources = ["arn:aws:kms:123456789:eu-west-1:key/hflksadhfldsk"]
		  }
		}
		`,
			mustExcludeResultCode: expectedCode,
		},
		{
			name: "denies access to any KMS resource",
			source: `
		resource "aws_iam_role_policy" "test_policy" {
		  name = "test_policy"
		  role = aws_iam_role.test_role.id

		  # Terraform's "jsonencode" function converts a
		  # Terraform expression result to valid JSON syntax.
		  policy = data.aws_iam_policy_document.kms_policy.json
		}

		resource "aws_iam_role" "test_role" {
		  name = "test_role"
		  assume_role_policy = jsonencode({
		    Version = "2012-10-17"
		    Statement = [
		      {
		        Action = "sts:AssumeRole"
		        Effect = "Allow"
		        Sid    = ""
		        Principal = {
		          Service = "ec2.amazonaws.com"
		        }
		      },
		    ]
		  })
		}

		data "aws_iam_policy_document" "kms_policy" {
		  statement {
		    principals {
		      type        = "AWS"
		      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
		    }
		    effect = "deny"
		    actions   = ["kms:*"]
		    resources = ["*"]
		  }
		}
		`,
			mustExcludeResultCode: expectedCode,
		},

		{
			name: "attaching a policy document containing * to non-IAM policy is allowed",
			source: `
		resource "aws_kms_key" "key" {
		  description         = "tfsec example"
		  policy              = data.aws_iam_policy_document.policy.json
		}

		data "aws_iam_policy_document" "policy" {
		  statement {
		    sid = "Admins"

		    effect = "Allow"

		    actions = ["kms:*"]

		    resources = [aws_kms_key.key.arn]

		    principals {
		      type        = "AWS"
		      identifiers = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
		    }
		  }
		}
		`,
			mustExcludeResultCode: expectedCode,
		},
		{
			name: "outright '*' in policy that contains KMS actions defined via json",
			source: `
		resource "aws_iam_role_policy" "test_policy" {
		  name = "test_policy"
		  role = aws_iam_role.test_role.id

		  # Terraform's "jsonencode" function converts a
		  # Terraform expression result to valid JSON syntax.
		  policy = jsonencode({
		    Version = "2012-10-17"
		    Statement = [
		      {
		        Action = [
		          "kms:*",
		        ]
		        Effect   = "Allow"
		        Resource = "*"
		      },
		    ]
		  })
		}

		resource "aws_iam_role" "test_role" {
		  name = "test_role"
		  assume_role_policy = jsonencode({
		    Version = "2012-10-17"
		    Statement = [
		      {
		        Action = "sts:AssumeRole"
		        Effect = "Allow"
		        Sid    = ""
		        Principal = {
		          Service = "ec2.amazonaws.com"
		        }
		      },
		    ]
		  })
		}
		`,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "Understands variables and introspects accordingly",
			source: `
variable "arn" {
  type = string
  default = "*"
}
resource "aws_iam_role_policy" "test_policy" {
  name = "test_policy"
  role = aws_iam_role.test_role.id

  # Terraform's "jsonencode" function converts a
  # Terraform expression result to valid JSON syntax.
  policy = data.aws_iam_policy_document.access_db_secrets.json
}

resource "aws_iam_role" "test_role" {
  name = "test_role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      },
    ]
  })
}

data "aws_iam_policy_document" "access_db_secrets" {
  statement {
    actions = [
      "kms:Decrypt"
    ]

    resources = [
      var.arn,
    ]
  }
}
`,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "Variable is unknown so we don't make determination of the pattern matches",
			source: `
resource "aws_iam_role_policy" "test_policy" {
  name = "test_policy"
  role = aws_iam_role.test_role.id

  # Terraform's "jsonencode" function converts a
  # Terraform expression result to valid JSON syntax.
  policy = data.aws_iam_policy_document.access_db_secrets.json
}

resource "aws_iam_role" "test_role" {
  name = "test_role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      },
    ]
  })
}

data "aws_iam_policy_document" "access_db_secrets" {
  statement {
    actions = [
      "kms:Decrypt"
    ]

    resources = [
      var.arn,
    ]
  }
}
`,
			mustExcludeResultCode: expectedCode,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			results := testutil.ScanHCL(test.source, t)
			testutil.AssertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
