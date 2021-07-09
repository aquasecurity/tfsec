resource "aws_lb" "test_lb" {

  tags = {
    Environment = "uat"
  }
}
