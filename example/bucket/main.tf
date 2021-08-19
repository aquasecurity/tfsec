resource "aws_s3_bucket" "unversioned_bucket" {

  name = "bad example"

  versioning {
    enabled = false
  }

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        kms_master_key_id = aws_kms_key.mykey.arn
        sse_algorithm     = "aws:kms"
      }
    }
  }
}


resource "aws_s3_bucket" "unencrypted_bucket" {
  name = "bad example"

  versioning {
     enabled = true
  }
}

resource "aws_s3_bucket" "with_logging_bucket" {

  name = "bad example"

  versioning {
    enabled = false
  }

  logging {
    enabled = true
  }

  server_side_encryption_configuration {
    rule {
    }
  }
}


