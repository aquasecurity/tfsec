variable "aws_region" {
  default = "eu-west-1"
}

variable "environment" {
  default = "dev"
}

provider "aws" {
  region = "eu-central-1"
}

terraform {
  # required_version = ">= 1.1.8"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 4.11.0"
    }
  }
}


locals {
  s3_buckets = {
    test_bucket = {
      force_destroy = false
      versioning    = "Enabled"
    }
    no_versioning_bucket = {
      force_destroy = false
      versioning    = "Disabled"
    }
  }

  shared_tags = {
    Environment = upper(var.environment)
  }
}


resource "aws_s3_bucket" "this" {
  for_each      = local.s3_buckets
  bucket_prefix = "${each.key}-"
  force_destroy = lookup(each.value, "force_destroy", false)
  tags = merge ({
    Name = upper(each.key)
  }, local.shared_tags)
}

resource "aws_s3_bucket_versioning" "this" {
  for_each = local.s3_buckets

  bucket = aws_s3_bucket.this[each.key].id
  versioning_configuration {
    status = lookup(each.value, "versioning", "Disabled")
  }
}
#
resource "aws_s3_bucket_public_access_block" "this" {
  for_each = local.s3_buckets

  bucket = aws_s3_bucket.this[each.key].id

  block_public_acls       = true
  block_public_policy     = true
  restrict_public_buckets = true
  ignore_public_acls      = true
}
#
resource "aws_s3_bucket_acl" "this" {
  for_each = local.s3_buckets
  bucket   = aws_s3_bucket.this[each.key].id
  acl      = "private"
}
#
resource "aws_kms_key" "this" {
  description             = "This key is used to encrypt bucket objects"
  deletion_window_in_days = 10
  enable_key_rotation     = true
}
#
resource "aws_s3_bucket_server_side_encryption_configuration" "encryption" {
  for_each = local.s3_buckets

  bucket = aws_s3_bucket.this[each.key].id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.this.arn
      sse_algorithm     = "aws:kms"
    }
  }
}


resource "aws_s3_bucket_logging" "example" {
  for_each = local.s3_buckets

  bucket = aws_s3_bucket.this[each.key].id

  target_bucket = ""
  target_prefix = "${each.key}-log/"
}