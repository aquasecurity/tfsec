
resource "aws_security_group_rule" "my-rule" {
    type        = "ingress"
    cidr_blocks = ["0.0.0.0/0"]
}

resource "aws_alb_listener" "my-alb-listener"{
    port     = "80"
    protocol = "HTTP"
}

resource "aws_db_security_group" "my-group" {

}

resource "azurerm_managed_disk" "source" {
    encryption_settings {
        enabled = false
    }
}