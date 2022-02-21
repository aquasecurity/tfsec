resource "aws_s3_bucket" "demo_bucket1" {
  bucket = "demo-bucket"
  acl    = "private"
  versioning {
    mfa_delete = true
  }
}