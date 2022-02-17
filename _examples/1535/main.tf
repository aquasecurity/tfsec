resource "aws_iam_role_policy" "test_policy" {
 	name = "test_policy"
 	role = aws_iam_role.test_role.id
 
 	policy = data.aws_iam_policy_document.service.json
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
 			Service = "s3.amazonaws.com"
 			}
 		},
 		]
	})
}

data "aws_iam_policy_document" "service" {
  statement {
    sid    = "AllowCloudWatchLogs"
    effect = "Allow"

    actions = [
      "logs:CreateLogGroup",
    ]

    resources = ["*"] # tfsec:ignore:aws-iam-no-policy-wildcards
  }

  statement {
    sid    = "AllowS3Write"
    effect = "Allow"

    actions = [
      "s3:GetObject"
    ]

    resources = ["*"]
  }
}
