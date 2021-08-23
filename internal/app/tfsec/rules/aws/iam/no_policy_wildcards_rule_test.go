package iam
// 
// // generator-locked
// import (
// 	"testing"
// 
// 	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
// )
// 
// func Test_AWSIAMPolicyShouldUsePrincipleOfLeastPrivilege(t *testing.T) {
// 	expectedCode := "aws-iam-no-policy-wildcards"
// 
// 	var tests = []struct {
// 		name                  string
// 		source                string
// 		mustIncludeResultCode string
// 		mustExcludeResultCode string
// 	}{
// 		{
// 			name: "Fails on wildcarded resource (inline)",
// 			source: `
// 				resource "aws_iam_role_policy" "test_policy" {
// 					name = "test_policy"
// 					role = aws_iam_role.test_role.id
// 
// 					policy = data.aws_iam_policy_document.s3_policy.json
// 				}
// 
// 				resource "aws_iam_role" "test_role" {
// 					name = "test_role"
// 					assume_role_policy = jsonencode({
// 						Version = "2012-10-17"
// 						Statement = [
// 						{
// 							Action = "sts:AssumeRole"
// 							Effect = "Allow"
// 							Sid    = ""
// 							Principal = {
// 							Service = "ec2.amazonaws.com"
// 							}
// 						},
// 						]
// 					})
// 				}
// 
// 				data "aws_iam_policy_document" "s3_policy" {
// 					statement {
// 						principals {
// 							type        = "AWS"
// 							identifiers = ["arn:aws:iam::1234567890:root"]
// 						}
// 						actions   = ["s3:GetObject"]
// 						resources = ["*"]
// 					}
// 				}
// 						`,
// 			mustIncludeResultCode: expectedCode,
// 		},
// 		{
// 			name: "Fails on wildcarded templated identifier (inline)",
// 			source: `
// 				resource "aws_iam_role_policy" "test_policy" {
// 					name = "test_policy"
// 					role = aws_iam_role.test_role.id
// 
// 					policy = data.aws_iam_policy_document.s3_policy.json
// 				}
// 
// 				resource "aws_iam_role" "test_role" {
// 					name = "test_role"
// 					assume_role_policy = jsonencode({
// 						Version = "2012-10-17"
// 						Statement = [
// 						{
// 							Action = "sts:AssumeRole"
// 							Effect = "Allow"
// 							Sid    = ""
// 							Principal = {
// 							Service = "ec2.amazonaws.com"
// 							}
// 						},
// 						]
// 					})
// 				}
// 
// 				data "aws_iam_policy_document" "s3_policy" {
// 					statement {
// 						principals {
// 							type        = "AWS"
// 							identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:*"]
// 						}
// 						actions   = ["s3:GetObject"]
// 						resources = ["asdasdasd"]
// 					}
// 				}
// 				`,
// 			mustIncludeResultCode: expectedCode,
// 		},
// 		{
// 			name: "Fails on wildcarded templated identifier with local (inline)",
// 			source: `
// 		resource "aws_iam_role_policy" "test_policy" {
// 			name = "test_policy"
// 			role = aws_iam_role.test_role.id
// 
// 			policy = data.aws_iam_policy_document.s3_policy.json
// 		}
// 
// 		resource "aws_iam_role" "test_role" {
// 			name = "test_role"
// 			assume_role_policy = jsonencode({
// 				Version = "2012-10-17"
// 				Statement = [
// 				{
// 					Action = "sts:AssumeRole"
// 					Effect = "Allow"
// 					Sid    = ""
// 					Principal = {
// 					Service = "ec2.amazonaws.com"
// 					}
// 				},
// 				]
// 			})
// 		}
// 
// 		locals {
// 			wildcard = "*"
// 		}
// 
// 		data "aws_iam_policy_document" "s3_policy" {
// 			statement {
// 				principals {
// 					type        = "AWS"
// 					identifiers = ["arn:aws:iam::${local.wildcard}:root"]
// 				}
// 				actions   = ["s3:GetObject"]
// 				resources = ["asdasdasd"]
// 			}
// 		}
// 		`,
// 			mustIncludeResultCode: expectedCode,
// 		},
// 		{
// 			name: "Fails on wildcarded templated identifier with variable (inline)",
// 			source: `
// 		resource "aws_iam_role_policy" "test_policy" {
// 			name = "test_policy"
// 			role = aws_iam_role.test_role.id
// 
// 			policy = data.aws_iam_policy_document.s3_policy.json
// 		}
// 
// 		resource "aws_iam_role" "test_role" {
// 			name = "test_role"
// 			assume_role_policy = jsonencode({
// 				Version = "2012-10-17"
// 				Statement = [
// 				{
// 					Action = "sts:AssumeRole"
// 					Effect = "Allow"
// 					Sid    = ""
// 					Principal = {
// 					Service = "ec2.amazonaws.com"
// 					}
// 				},
// 				]
// 			})
// 		}
// 
// 		variable "wildcard" {
// 			default = "*"
// 		}
// 
// 		data "aws_iam_policy_document" "s3_policy" {
// 			statement {
// 				principals {
// 					type        = "AWS"
// 					identifiers = [var.wildcard]
// 				}
// 				actions   = ["s3:GetObject"]
// 				resources = ["asdasdasd"]
// 			}
// 		}
// 		`,
// 			mustIncludeResultCode: expectedCode,
// 		},
// 		{
// 			name: "Fails on wildcarded action (inline)",
// 			source: `
// resource "aws_iam_role_policy" "test_policy" {
// 	name = "test_policy"
// 	role = aws_iam_role.test_role.id
// 
// 	policy = data.aws_iam_policy_document.s3_policy.json
// }
// 
// resource "aws_iam_role" "test_role" {
// 	name = "test_role"
// 	assume_role_policy = jsonencode({
// 		Version = "2012-10-17"
// 		Statement = [
// 		{
// 			Action = "sts:AssumeRole"
// 			Effect = "Allow"
// 			Sid    = ""
// 			Principal = {
// 			Service = "s3.amazonaws.com"
// 			}
// 		},
// 		]
// 	})
// }
// 
// data "aws_iam_policy_document" "s3_policy" {
// 	statement {
// 	principals {
// 		type        = "AWS"
// 		identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
// 	}
// 	actions   = ["s3:*"]
// 	resources = ["something:blah"]
// 	}
// }
// `,
// 			mustIncludeResultCode: expectedCode,
// 		},
// 		{
// 			name: "Fails on wildcarded principal (inline)",
// 			source: `
// resource "aws_iam_role_policy" "test_policy" {
// 	name = "test_policy"
// 	role = aws_iam_role.test_role.id
// 
// 	policy = data.aws_iam_policy_document.s3_policy.json
// }
// 
// resource "aws_iam_role" "test_role" {
// 	name = "test_role"
// 	assume_role_policy = jsonencode({
// 		Version = "2012-10-17"
// 		Statement = [
// 		{
// 			Action = "sts:AssumeRole"
// 			Effect = "Allow"
// 			Sid    = ""
// 			Principal = {
// 				Service = "s3.amazonaws.com"
// 			}
// 		},
// 		]
// 	})
// }
// 
// data "aws_iam_policy_document" "s3_policy" {
// 	statement {
// 	principals {
// 		type        = "AWS"
// 		identifiers = ["*"]
// 	}
// 	actions   = ["s3:GetObject"]
// 	resources = ["something:exact"]
// 	}
// }
// `,
// 			mustIncludeResultCode: expectedCode,
// 		},
// 		{
// 			name: "Fails on wildcarded resource (json)",
// 			source: `
// resource "aws_iam_role_policy" "test_policy" {
// 	name = "test_policy"
// 	role = aws_iam_role.test_role.id
// 
// 	policy = <<EOF
// {
// 	"Version": "2012-10-17",
// 	"Statement": [
// 		{
// 			"Sid": "ListYourObjects",
// 			"Effect": "Allow",
// 			"Action": "s3:ListBucket",
// 			"Resource": ["arn:aws:s3:::*"],
// 			"Principal": {
// 				"AWS": "arn:aws:iam::1234567890:root"
// 			}
// 		}
// 	]
// }
// EOF
// }
// 
// resource "aws_iam_role" "test_role" {
// 	name = "test_role"
// 	assume_role_policy = jsonencode({
// 		Version = "2012-10-17"
// 		Statement = [
// 		{
// 			Action = "sts:AssumeRole"
// 			Effect = "Allow"
// 			Sid    = ""
// 			Principal = {
// 				Service = "s3.amazonaws.com"
// 			}
// 		},
// 		]
// 	})
// }
// 
// `,
// 			mustIncludeResultCode: expectedCode,
// 		},
// 		{
// 			name: "Fails on wildcarded action (json)",
// 			source: `
// resource "aws_iam_role_policy" "test_policy" {
// 	name = "test_policy"
// 	role = aws_iam_role.test_role.id
// 
// 	policy = <<EOF
// {
// 	"Version": "2012-10-17",
// 	"Statement": [
// 		{
// 			"Sid": "ListYourObjects",
// 			"Effect": "Allow",
// 			"Action": "s3:*",
// 			"Resource": ["arn:aws:s3:::bucket-name"],
// 			"Principal": {
// 				"AWS": "arn:aws:iam::1234567890:root"
// 			}
// 		}
// 	]
// }
// EOF
// }
// 
// resource "aws_iam_role" "test_role" {
// 	name = "test_role"
// 	assume_role_policy = jsonencode({
// 		Version = "2012-10-17"
// 		Statement = [
// 		{
// 			Action = "sts:AssumeRole"
// 			Effect = "Allow"
// 			Sid    = ""
// 			Principal = {
// 				Service = "s3.amazonaws.com"
// 			}
// 		},
// 		]
// 	})
// }
// 
// `,
// 			mustIncludeResultCode: expectedCode,
// 		},
// 		{
// 			name: "Fails on wildcarded principal (json)",
// 			source: `
// resource "aws_iam_role_policy" "test_policy" {
// 	name = "test_policy"
// 	role = aws_iam_role.test_role.id
// 
// 	policy = <<EOF
// {
// 	"Version": "2012-10-17",
// 	"Statement": [
// 		{
// 			"Sid": "ListYourObjects",
// 			"Effect": "Allow",
// 			"Action": "s3:ListBucket",
// 			"Resource": ["arn:aws:s3:::bucket-name"],
// 			"Principal": {
// 				"AWS": "arn:aws:iam::1234567890:*"
// 			}
// 		}
// 	]
// }
// EOF
// }
// 
// resource "aws_iam_role" "test_role" {
// 	name = "test_role"
// 	assume_role_policy = jsonencode({
// 		Version = "2012-10-17"
// 		Statement = [
// 		{
// 			Action = "sts:AssumeRole"
// 			Effect = "Allow"
// 			Sid    = ""
// 			Principal = {
// 				Service = "s3.amazonaws.com"
// 			}
// 		},
// 		]
// 	})
// }
// 
// `,
// 			mustIncludeResultCode: expectedCode,
// 		},
// 		{
// 			name: "Passes without wildcard usage",
// 			source: `
// resource "aws_iam_role_policy" "test_policy" {
// 	name = "test_policy"
// 	role = aws_iam_role.test_role.id
// 
// 	policy = data.aws_iam_policy_document.s3_policy.json
// }
// 
// resource "aws_iam_role" "test_role" {
// 	name = "test_role"
// 	assume_role_policy = jsonencode({
// 		Version = "2012-10-17"
// 		Statement = [
// 		{
// 			Action = "sts:AssumeRole"
// 			Effect = "Allow"
// 			Sid    = ""
// 			Principal = {
// 				Service = "s3.amazonaws.com"
// 			}
// 		},
// 		]
// 	})
// }
// 
// data "aws_iam_policy_document" "s3_policy" {
// 	statement {
// 	principals {
// 		type        = "AWS"
// 		identifiers = ["aws:arn:21345/blah"]
// 	}
// 	actions   = ["s3:GetObject"]
// 	resources = ["something:exact"]
// 	}
// }
// `,
// 			mustExcludeResultCode: expectedCode,
// 		},
// 		{
// 			name: "Passes when resource is star and action is inspector (hcl)",
// 			source: `
// resource "aws_iam_role_policy" "test_policy" {
// 	name = "test_policy"
// 	role = aws_iam_role.test_role.id
// 
// 	policy = data.aws_iam_policy_document.s3_policy.json
// }
// 
// resource "aws_iam_role" "test_role" {
// 	name = "test_role"
// 	assume_role_policy = jsonencode({
// 		Version = "2012-10-17"
// 		Statement = [
// 		{
// 			Action = "sts:AssumeRole"
// 			Effect = "Allow"
// 			Sid    = ""
// 			Principal = {
// 				Service = "s3.amazonaws.com"
// 			}
// 		},
// 		]
// 	})
// }
// 
// data "aws_iam_policy_document" "s3_policy" {
// 	statement {
// 	principals {
// 		type        = "AWS"
// 		identifiers = ["aws:arn:21345/blah"]
// 	}
// 	actions   = ["inspector:StartAssessmentRun"]
// 	resources = ["*"]
// 	}
// }
// `,
// 			mustExcludeResultCode: expectedCode,
// 		},
// 		{
// 			name: "Passes when resource is star and action is inspector (hcl)",
// 			source: `
// resource "aws_iam_role_policy" "test_policy" {
// 	name = "test_policy"
// 	role = aws_iam_role.test_role.id
// 
// 	policy = data.aws_iam_policy_document.s3_policy.json
// }
// 
// resource "aws_iam_role" "test_role" {
// 	name = "test_role"
// 	assume_role_policy = jsonencode({
// 		Version = "2012-10-17"
// 		Statement = [
// 		{
// 			Action = "sts:AssumeRole"
// 			Effect = "Allow"
// 			Sid    = ""
// 			Principal = {
// 				Service = "s3.amazonaws.com"
// 			}
// 		},
// 		]
// 	})
// }
// 
// data "aws_iam_policy_document" "s3_policy" {
// 	statement {
// 	principals {
// 		type        = "AWS"
// 		identifiers = ["aws:arn:21345/blah"]
// 	}
// 	actions   = ["iam:ListVirtualMFADevices"]
// 	resources = ["*"]
// 	}
// }
// `,
// 			mustExcludeResultCode: expectedCode,
// 		},
// 		{
// 			name: "Passes when resource is star and action is inspector (json)",
// 			source: `
// resource "aws_iam_role_policy" "test_policy" {
// 	name = "test_policy"
// 	role = aws_iam_role.test_role.id
// 
// 	policy = <<EOF
// {
// 	"Version": "2012-10-17",
// 	"Statement": [
// 		{
// 			"Sid": "ListYourObjects",
// 			"Effect": "Allow",
// 			"Action": "s3:ListBucket",
// 			"Resource": ["arn:aws:s3:::bucket-name"],
// 			"Principal": {
// 				"AWS": "arn:aws:iam::1234567890:*"
// 			}
// 		}
// 	]
// }
// EOF
// }
// 
// resource "aws_iam_role" "test_role" {
// 	name = "test_role"
// 	assume_role_policy = jsonencode({
// 		Version = "2012-10-17"
// 		Statement = [
// 		{
// 			Action    = "inspector:StartAssessmentRun"
// 			Effect    = "Allow"
// 			Sid       = ""
// 			Resource  = ["*"]
// 			Principal = {
// 				Service = "s3.amazonaws.com"
// 			}
// 		},
// 		]
// 	})
// }
// 
// `,
// 			mustIncludeResultCode: expectedCode,
// 		},
// 	}
// 
// 	for _, test := range tests {
// 		t.Run(test.name, func(t *testing.T) {
// 
// 			results := testutil.ScanHCL(test.source, t)
// 			testutil.AssertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
// 		})
// 	}
// 
// }
