package test

import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/rules"
)

func Test_AWSUnencryptedMSKBroker(t *testing.T) {
	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name:                  "check MSK broker with encryption_info not set",
			source:                `resource "aws_msk_cluster" "msk-cluster" {}`,
			mustIncludeResultCode: rules.AWSUnencryptedMSKBroker,
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
			mustIncludeResultCode: rules.AWSUnencryptedMSKBroker,
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
			mustIncludeResultCode: rules.AWSUnencryptedMSKBroker,
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
			mustIncludeResultCode: rules.AWSUnencryptedMSKBroker,
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
			mustIncludeResultCode: rules.AWSUnencryptedMSKBroker,
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
			mustExcludeResultCode: rules.AWSUnencryptedMSKBroker,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanHCL(test.source, t)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}
}
