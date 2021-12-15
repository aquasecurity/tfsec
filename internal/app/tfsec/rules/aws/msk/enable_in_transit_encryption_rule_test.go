package msk

import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
)

func Test_AWSUnencryptedMSKBroker(t *testing.T) {
	expectedCode := "aws-msk-enable-in-transit-encryption"
	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name:                  "check MSK broker with encryption_info not set",
			source:                `resource "aws_msk_cluster" "msk-cluster" {}`,
			mustIncludeResultCode: expectedCode,
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
			mustIncludeResultCode: expectedCode,
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
			mustIncludeResultCode: expectedCode,
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
			mustIncludeResultCode: expectedCode,
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
			mustIncludeResultCode: expectedCode,
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
			mustExcludeResultCode: expectedCode,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			results := testutil.ScanHCL(test.source, t)
			testutil.AssertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}
}
