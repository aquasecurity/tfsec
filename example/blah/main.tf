
provider "aws" {
  region = "us-east-1"
  access_key = "123"
  secret_key = "xyz"
  skip_credentials_validation = true
  skip_requesting_account_id = true
  skip_metadata_api_check = true
  s3_force_path_style = true
  endpoints {
    s3 = "http://localhost:4572"
  }
}


		resource "aws_s3_bucket" "bucket" {
			for_each      = toset(["example1", "example2"])
			bucket        = each.value
		}

		resource "aws_s3_bucket_public_access_block" "pab" {
			for_each = aws_s3_bucket.bucket
			bucket   = each.value.id

			block_public_acls       = true
			block_public_policy     = true
		}

