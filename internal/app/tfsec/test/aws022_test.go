package test

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/checks"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

func Test_AWSUnencryptedMSKBroker(t *testing.T) {
	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode scanner.RuleCode
		mustExcludeResultCode scanner.RuleCode
	}{
		{
			name:                  "check MSK broker with encryption_info not set",
			source:                `resource "aws_msk_cluster" "msk-cluster" {}`,
			mustIncludeResultCode: checks.AWSUnencryptedMSKBroker,
		},
		{
			name: "check MSK broker with encryption_in_transit not set",
			source: `
resource "aws_msk_cluster" "msk-cluster" {
	encryption_info {
		encryption_in_transit {
			client_broker = "TLS_PLAINTEXT"
			in_cluster = true
		}
	}
}`,
			mustIncludeResultCode: checks.AWSUnencryptedMSKBroker,
		},
		{
			name: "check MSK broker with client_broker not set",
			source: `
resource "aws_msk_cluster" "msk-cluster" {
	encryption_info {
		encryption_in_transit {
		}
	}
}`,
			mustIncludeResultCode: checks.AWSUnencryptedMSKBroker,
		},
		{
			name: "check MSK broker with client_broker set to PLAINTEXT",
			source: `
resource "aws_msk_cluster" "msk-cluster" {
	encryption_info {
		encryption_in_transit {
			client_broker = "PLAINTEXT"
		}
	}
}`,
			mustIncludeResultCode: checks.AWSUnencryptedMSKBroker,
		},
		{
			name: "check MSK broker with client_broker set to TLS_PLAINTEXT",
			source: `
resource "aws_msk_cluster" "msk-cluster" {
	encryption_info {
		encryption_in_transit {
			client_broker = "TLS_PLAINTEXT"
		}
	}
}`,
			mustIncludeResultCode: checks.AWSUnencryptedMSKBroker,
		},
		{
			name: "check MSK broker with client_broker set to TLS",
			source: `
resource "aws_msk_cluster" "msk-cluster" {
	encryption_info {
		encryption_in_transit {
			client_broker = "TLS"
		}
	}
}`,
			mustExcludeResultCode: checks.AWSUnencryptedMSKBroker,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}
}
