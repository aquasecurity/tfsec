resource "aws_s3_bucket" "custom_module_bucket" {
  bucket = "my-custom-module-bucket"
  acl    = "private"

  versioning {
    enabled = true
  }
}