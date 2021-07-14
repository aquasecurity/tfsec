resource "aws_security_group_rule" "trust-rules-dev" {
	count = 4
	description = var.trust-sg-rules[count.index]["description"]
	type = "ingress"
	protocol = "tcp"
	cidr_blocks = ["0.0.0.0/2"]
	to_port = var.trust-sg-rules[count.index]["to_port"]
	from_port = 10
	security_group_id = aws_security_group.trust-rules-dev.id
}
	
resource "aws_security_group" "trust-rules-dev" {
	description = "description"
}
	
variable "trust-sg-rules" {
	description = "A list of maps that creates a number of sg"
	type = list(map(string))
	
	default = [
		{
			description = "Allow egress of http traffic"
			from_port = "80"
			to_port = "80"
			type = "egress"
		},
		{
			description = "Allow egress of http traffic"
			from_port = "80"
			to_port = "80"
			type = "egress"
		}
	]
}