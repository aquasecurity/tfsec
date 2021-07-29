
resource "aws_security_group_rule" "my-rule" {
  type        = "ingress"
  cidr_blocks = ["0.0.0.0/0"]
}

resource "aws_alb_listener" "my-alb-listener" {
  port     = "80"
  protocol = "HTTP"
}

resource "aws_db_security_group" "my-group" {

}

resource "aws_instance" "bad_user_data" {
  user_data = <<EOF
DB_PASSWORD = "Some passwprkd"
EOF
}

variable "enableEncryption" {
  default = false
}

#tfsec:ignore:azure-compute-enable-disk-encryption
resource "azurerm_managed_disk" "source" {
  encryption_settings {
    enabled = var.enableEncryption
  }
}

resource "aws_api_gateway_domain_name" "missing_security_policy" {
}

resource "aws_api_gateway_domain_name" "empty_security_policy" {
  security_policy = ""
}

resource "aws_api_gateway_domain_name" "outdated_security_policy" {
  security_policy = "TLS_1_0"
}

resource "aws_api_gateway_domain_name" "valid_security_policy" {
  security_policy = "TLS_1_2"
}

#tfsec:ignore:AWS092
resource "aws_dynamodb_table" "bad_example" {
  name             = "example"
  hash_key         = "TestTableHashKey"
  billing_mode     = "PAY_PER_REQUEST"
  stream_enabled   = true
  stream_view_type = "NEW_AND_OLD_IMAGES"

  attribute {
    name = "TestTableHashKey"
    type = "S"
  }

  point_in_time_recovery {
    enabled = true
  }
}

resource "aws_instance" "my_project" {

}
