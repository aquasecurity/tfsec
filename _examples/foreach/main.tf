
locals{
  prefix = "blah"
}

# tfsec:ignore:AWS002 tfsec:ignore:AWS017 tfsec:ignore:AWS077
resource "aws_s3_bucket" "for_web" {
  for_each = var.targets

  bucket = "${local.prefix}-${lookup(each.value, "name")}-web"
  acl    = "private"

  versioning {
    enabled    = false
    mfa_delete = false
  }

  tags = {
    Name = "${local.prefix}-${lookup(each.value, "name")}-web"
  }
}

resource "aws_s3_bucket_public_access_block" "for_web_public" {
  for_each = var.targets2

  bucket = aws_s3_bucket.for_web[each.key].id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

variable "targets" {
  default={
    "a" = {
      name = "test"
    },
    "b" = {
      name = "test"
    },
    "c" = {
      name = "test"
    }
  }
}


variable "targets2" {
  default={
    "a" = {
      name = "test"
    },
    "b" = {
      name = "test"
    }
  }
}
