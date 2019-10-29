package tfsec

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_AWSNotInternal(t *testing.T) {

	var tests = []struct {
		name           string
		source         string
		expectsResults bool
	}{
		{
			name: "check aws_alb when not internal",
			source: `
resource "aws_alb" "my-resource" {
	internal = false
}`,
			expectsResults: true,
		},
		{
			name: "check aws_elb when not internal",
			source: `
resource "aws_elb" "my-resource" {
	internal = false
}`,
			expectsResults: true,
		},
		{
			name: "check aws_lb when not internal",
			source: `
resource "aws_lb" "my-resource" {
	internal = false
}`,
			expectsResults: true,
		},
		{
			name: "check aws_lb when not explicitly marked as internal",
			source: `
resource "aws_lb" "my-resource" {
}`,
			expectsResults: true,
		},
		{
			name: "check aws_lb when explicitly marked as internal",
			source: `
resource "aws_lb" "my-resource" {
	internal = true
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
