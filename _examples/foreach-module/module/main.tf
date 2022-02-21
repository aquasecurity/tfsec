
resource "aws_s3_bucket" "for_web" {

  bucket = var.bucket
  acl    = "private"

  versioning {
    enabled    = false
    mfa_delete = false
  }
}

resource "aws_s3_bucket_public_access_block" "for_web_public" {

  bucket = aws_s3_bucket.for_web.bucket

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
