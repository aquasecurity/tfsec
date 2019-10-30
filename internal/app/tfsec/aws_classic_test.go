package tfsec

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_AWSClassicUsage(t *testing.T) {

	var tests = []struct {
		name           string
		source         string
		expectsResults bool
	}{
		{
			name:           "check aws_db_security_group",
			source:         `resource "aws_db_security_group" "my-group" {}`,
			expectsResults: true,
		},
		{
			name:           "check aws_redshift_security_group",
			source:         `resource "aws_redshift_security_group" "my-group" {}`,
			expectsResults: true,
		},
		{
			name:           "check aws_elasticache_security_group",
			source:         `resource "aws_elasticache_security_group" "my-group" {}`,
			expectsResults: true,
		},
		{
			name:           "check for false positives",
			source:         `resource "my_resource" "my-resource" {}`,
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
