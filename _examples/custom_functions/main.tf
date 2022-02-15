resource "aws_instance" "bastion" {
  metadata_options {
    http_endpoint               = "enabled"
    http_put_response_hop_limit = 1
    http_tokens                 = "required"
  }

  tags = {
    Environment = "test"
  }
}


resource "aws_s3_bucket" "disabled_versioned_bucket" {
  bucket = "my-tf-test-bucket"
  acl    = "private"

  versioning {
    enabled = true
  }

  tags = {
    "CostCentre" : "CD0012"
  }
}
