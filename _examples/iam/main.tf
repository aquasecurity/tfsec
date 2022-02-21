resource "aws_iam_policy" "policy" {
  name        = "${random_pet.pet_name.id}-policy"
  description = "My test policy"




  policy = <<EOT
  {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Action": [
          "s3:ListAllMyBuckets"
        ],
        "Effect": "Allow",
        "Resource": "*"
      },
      {
        "Action": [        "s3:*"      ],
        "Effect": "Allow",
        "Resource": "my-bucket"
      }
    ]
  }
EOT
}