resource "aws_instance" "non_compliant" {
  ami           = "ami-1234"
  instance_type = "t2.small"

  tags = {
    Department = "Finance"
  }

}

resource "aws_instance" "compliant" {
  ami            = "ami-12345"
  instance_type  = "t2.small"
  cpu_core_count = 4

  tags = {
    Department = "Finance"
    CostCentre = "CC1234"
  }
}

resource "aws_s3_bucket" "unversioned_bucket" {
  bucket = "my-tf-test-bucket"
  acl    = "private"
}

#tfsec:ignore:AWS017:exp:2021-01-01:ws:testworkspace
resource "aws_s3_bucket" "versioned_bucket" {
  bucket = "my-tf-test-bucket"
  acl    = "private"

  versioning {
    enabled = true
  }
}
# tfsec:ignore:AWS017  
resource "aws_s3_bucket" "disabled_versioned_bucket" {
  bucket = "my-tf-test-bucket"
  acl    = "private"

  versioning {
    enabled = true
  }
}

module "custom_bucket" {
  source      = "./modules/public_custom_bucket"
  bucket_name = "new-public-bucket"
  acl         = "private"
}

#tfsec:ignore:aws-s3-enable-bucket-encryption
resource "aws_s3_bucket" "bucket_with_public_acl" {
  bucket = "my-tf-test-bucket"
  //  acl    = "public-read"
  //
  versioning {
    enabled = true
  }
}
