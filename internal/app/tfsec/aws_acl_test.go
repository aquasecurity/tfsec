package tfsec

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_AWSACL(t *testing.T) {

	var tests = []struct {
		name           string
		source         string
		expectsResults bool
	}{
		{
			name: "check aws_s3_bucket with acl=public-read",
			source: `
resource "aws_s3_bucket" "my-bucket" {
	acl = "public-read"
}`,
			expectsResults: true,
		},
		{
			name: "check aws_s3_bucket with acl=public-read-write",
			source: `
resource "aws_s3_bucket" "my-bucket" {
	acl = "public-read-write"
}`,
			expectsResults: true,
		},
		{
			name: "check aws_s3_bucket with acl=website",
			source: `
resource "aws_s3_bucket" "my-bucket" {
	acl = "website"
}`,
			expectsResults: true,
		},
		{
			name: "check aws_s3_bucket with acl=private",
			source: `
resource "aws_s3_bucket" "my-bucket" {
	acl = "private"
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
