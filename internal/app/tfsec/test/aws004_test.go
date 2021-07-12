package test

import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/rules"
)

func Test_AWSPlainHTTP(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "check aws_alb_listener using plain HTTP",
			source: `
resource "aws_alb_listener" "my-listener" {
	protocol = "HTTP"
}`,
			mustIncludeResultCode: rules.AWSPlainHTTP,
		},
		{
			name: "check aws_lb_listener using plain HTTP",
			source: `
resource "aws_lb_listener" "my-listener" {
	protocol = "HTTP"
}`,
			mustIncludeResultCode: rules.AWSPlainHTTP,
		},
		{
			name: "check aws_alb_listener using plain HTTP (via non specification)",
			source: `
resource "aws_alb_listener" "my-listener" {
}`,
			mustIncludeResultCode: rules.AWSPlainHTTP,
		},
		{
			name: "check aws_alb_listeneer should continue checks if the referenced if a load balancer is not gateway",
			source: `
resource "aws_lb" "gwlb" {

	load_balancer_type = "application"

}

resource "aws_lb_listener" "gwlb_listener" {
	load_balancer_arn = aws_lb.gwlb.id
	  
	default_action {
		target_group_arn = aws_lb_target_group.gwlb_target_group.id
		  type             = "forward"
		}
}
	`,
			mustIncludeResultCode: rules.AWSPlainHTTP,
		},
		{
			name: "check aws_alb_listener using HTTPS",
			source: `
resource "aws_alb_listener" "my-listener" {
	protocol = "HTTPS"
}`,
			mustExcludeResultCode: rules.AWSPlainHTTP,
		},
		{
			name: "check aws_alb_listener using HTTP as redirect to HTTPS",
			source: `
resource "aws_alb_listener" "my-listener" {
	protocol = "HTTP"
	default_action {
		type = "redirect"

		redirect {
			port        = "443"
			protocol    = "HTTPS"
			status_code = "HTTP_301"
		}
	}
}`,
			mustExcludeResultCode: rules.AWSPlainHTTP,
		},
		{
			name: "check aws_alb_listeneer should pass if a type is gateway",
			source: `
resource "aws_lb" "gwlb" {

	load_balancer_type = "gateway"

}

resource "aws_lb_listener" "gwlb_listener" {
	load_balancer_arn = aws_lb.gwlb.id
	  
	default_action {
		target_group_arn = aws_lb_target_group.gwlb_target_group.id
		  type             = "forward"
		}
}
	`,
			mustExcludeResultCode: rules.AWSPlainHTTP,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanHCL(test.source, t)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
