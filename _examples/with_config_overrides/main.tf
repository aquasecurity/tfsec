resource "aws_s3_bucket" "for_web" {
  bucket = "${local.prefix}-${lookup(each.value, "name")}-web"
  acl    = "private"

  tags = {
    Name = "${local.prefix}-${lookup(each.value, "name")}-web"
  }
}