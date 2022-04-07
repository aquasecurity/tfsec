
resource "aws_cloudtrail" "good_example" {
  is_multi_region_trail      = true
  enable_log_file_validation = true
  kms_key_id                 = "something"
}
