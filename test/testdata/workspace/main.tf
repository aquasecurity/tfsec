resource "aws_s3_bucket" "maybe" {
  count = terraform.workspace == "default" ? 10 : 0
}