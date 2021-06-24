package test

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/rules"
)

func Test_AWSNotInternal(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "check aws_alb when not internal",
			source: `
resource "aws_alb" "my-resource" {
	internal = false
}`,
			mustIncludeResultCode: rules.AWSExternallyExposedLoadBalancer,
		},
		{
			name: "check aws_elb when not internal",
			source: `
resource "aws_elb" "my-resource" {
	internal = false
}`,
			mustIncludeResultCode: rules.AWSExternallyExposedLoadBalancer,
		},
		{
			name: "check aws_lb when not internal",
			source: `
resource "aws_lb" "my-resource" {
	internal = false
}`,
			mustIncludeResultCode: rules.AWSExternallyExposedLoadBalancer,
		},
		{
			name: "check aws_lb when not explicitly marked as internal",
			source: `
resource "aws_lb" "my-resource" {
}`,
			mustIncludeResultCode: rules.AWSExternallyExposedLoadBalancer,
		},
		{
			name: "check aws_lb when explicitly marked as internal",
			source: `
resource "aws_lb" "my-resource" {
	internal = true
}`,
			mustExcludeResultCode: rules.AWSExternallyExposedLoadBalancer,
		},
		{
			name: "check aws_lb when explicitly is a gateway",
			source: `
resource "aws_lb" "gwlb" {
	name               = var.gwlb_name
	load_balancer_type = "gateway"
	subnets            = local.appliance_subnets_id
  }`,
			mustExcludeResultCode: rules.AWSExternallyExposedLoadBalancer,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
