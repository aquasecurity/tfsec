package rds

import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
)

func Test_AWSRDSEncryptionNotEnabled(t *testing.T) {
	expectedCode := "aws-rds-encrypt-instance-storage-data"

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "Encryption not enabled on db instance",
			source: `
 resource "aws_db_instance" "my-db-instance" {
 	
 }
 `,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "Encryption not enabled on db instance",
			source: `
 resource "aws_db_instance" "my-db-instance" {
 	storage_encrypted = false
 }
 `,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "Encryption not enabled on db instance",
			source: `
 resource "aws_db_instance" "my-db-instance" {
 	kms_key_id = "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"
 }
 `,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "Encryption using specified CMK enabled on db instance",
			source: `
 resource "aws_db_instance" "my-db-instance" {
 	storage_encrypted = true
 	kms_key_id = "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"
 }
 `,
			mustExcludeResultCode: expectedCode,
		},
		{
			name: "Encryption using default CMK enabled on db instance",
			source: `
 resource "aws_db_instance" "my-db-instance" {
 	storage_encrypted = true
 }
 `,
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
