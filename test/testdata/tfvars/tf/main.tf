
variable "bucket_count" {
  default = 0
}

resource "aws_s3_bucket" "bad" {
  count = var.bucket_count
}
