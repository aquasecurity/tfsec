resource "aws_s3_bucket" "panic" {
  # this will trigger a panic in the tests
  bucket = "panic"
}