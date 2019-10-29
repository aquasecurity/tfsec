package tfsec

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_AWSOutdatedSSLPolicy(t *testing.T) {

	var tests = []struct {
		name           string
		source         string
		expectsResults bool
	}{
		{
			name: "check aws_alb_listener with outdated policy",
			source: `
resource "aws_alb_listener" "my-resource" {
	ssl_policy = "ELBSecurityPolicy-TLS-1-1-2017-01"
	protocol = "HTTPS"
}`,
			expectsResults: true,
		},
		{
			name: "check aws_lb_listener with outdated policy",
			source: `
resource "aws_lb_listener" "my-resource" {
	ssl_policy = "ELBSecurityPolicy-TLS-1-1-2017-01"
	protocol = "HTTPS"
}`,
			expectsResults: true,
		},
		{
			name: "check aws_alb_listener with ok policy",
			source: `
resource "aws_alb_listener" "my-resource" {
	ssl_policy = "ELBSecurityPolicy-TLS-1-2-2017-01"
	protocol = "HTTPS"
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
