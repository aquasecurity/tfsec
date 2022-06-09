resource "aws_s3_bucket" "custom_module_bucket" {
  bucket = var.bucket_name
  acl    = var.acl

  versioning {
    enabled = true
  }
}

variable "bucket_name" {
  type        = string
  description = "The name of the bucket"
}

variable "acl" {
  type        = string
  description = "The acl to use"
}