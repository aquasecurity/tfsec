locals {
  bucket_id = aws_s3_bucket.test[0].id
}

resource "aws_s3_bucket" "test" {
  count         = 1
  bucket_prefix = "test_"
}

resource "aws_s3_bucket_public_access_block" "deny_public_access" {
  bucket = local.bucket_id

  block_public_acls       = true
  block_public_policy     = true
  restrict_public_buckets = true
}