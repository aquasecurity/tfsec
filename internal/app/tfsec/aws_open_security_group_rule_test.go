package tfsec

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_AWSOpenSecurityGroupRule(t *testing.T) {

	var tests = []struct {
		name           string
		source         string
		expectsResults bool
	}{
		{
			name: "check aws_security_group_rule ingress on 0.0.0.0/0",
			source: `
resource "aws_security_group_rule" "my-rule" {
	type = "ingress"
	cidr_blocks = ["0.0.0.0/0"]
}`,
			expectsResults: true,
		},
		{
			name: "check aws_security_group_rule egress on 0.0.0.0/0",
			source: `
resource "aws_security_group_rule" "my-rule" {
	type = "egress"
	cidr_blocks = ["0.0.0.0/0"]
}`,
			expectsResults: true,
		},
		{
			name: "check aws_security_group_rule egress on 0.0.0.0/0 in list",
			source: `
resource "aws_security_group_rule" "my-rule" {
	type = "egress"
	cidr_blocks = ["10.0.0.0/16", "0.0.0.0/0"]
}`,
			expectsResults: true,
		},
		{
			name: "check aws_security_group_rule egress on 10.0.0.0/16",
			source: `
resource "aws_security_group_rule" "my-rule" {
	type = "egress"
	cidr_blocks = ["10.0.0.0/16"]
}`,
			expectsResults: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assert.Equal(t, test.expectsResults, len(results) > 0)
		})
	}

}
