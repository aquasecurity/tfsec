resource "aws_alb_listener" "my-alb-listener" {
  port     = "443"
  protocol = "HTTPS"
}
