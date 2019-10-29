package tfsec

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_AWSPublic(t *testing.T) {

	var tests = []struct {
		name           string
		source         string
		expectsResults bool
	}{
		{
			name: "check aws_db_instance when publicly exposed",
			source: `
resource "aws_db_instance" "my-resource" {
	publicly_accessible = true
}`,
			expectsResults: true,
		},
		{
			name: "check aws_dms_replication_instance when publicly exposed",
			source: `
resource "aws_dms_replication_instance" "my-resource" {
	publicly_accessible = true
}`,
			expectsResults: true,
		},
		{
			name: "check aws_rds_cluster_instance when publicly exposed",
			source: `
resource "aws_rds_cluster_instance" "my-resource" {
	publicly_accessible = true
}`,
			expectsResults: true,
		},
		{
			name: "check aws_redshift_cluster when publicly exposed",
			source: `
resource "aws_redshift_cluster" "my-resource" {
	publicly_accessible = true
}`,
			expectsResults: true,
		},
		{
			name: "check aws_redshift_cluster when not publicly exposed",
			source: `
resource "aws_redshift_cluster" "my-resource" {
	publicly_accessible = false
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
