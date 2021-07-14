package test

import (
	"testing"
)

func Test_ResourcesWithCount(t *testing.T) {
	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "unspecified count defaults to 1",
			source: `
			resource "aws_default_vpc" "this" {}
`,
			mustIncludeResultCode: "AWS082",
		},
		{
			name: "count is literal 1",
			source: `
			resource "aws_default_vpc" "this" {
				count = 1
			}
`,
			mustIncludeResultCode: "AWS082",
		},
		{
			name: "count is literal 99",
			source: `
			resource "aws_default_vpc" "this" {
				count = 99
			}
`,
			mustIncludeResultCode: "AWS082",
		},
		{
			name: "count is literal 0",
			source: `
			resource "aws_default_vpc" "this" {
				count = 0
			}
`,
			mustExcludeResultCode: "AWS082",
		},
		{
			name: "count is 0 from variable",
			source: `
			variable "count" {
				default = 0
			}
			resource "aws_default_vpc" "this" {
				count = var.count
			}
`,
			mustExcludeResultCode: "AWS082",
		},
		{
			name: "count is 1 from variable",
			source: `
			variable "count" {
				default = 1
			}
			resource "aws_default_vpc" "this" {
				count =  var.count
			}
`,
			mustIncludeResultCode: "AWS082",
		},
		{
			name: "count is 0 from conditional",
			source: `
			variable "enabled" {
				default = false
			}
			resource "aws_default_vpc" "this" {
				count = var.enabled ? 1 : 0
			}
`,
			mustExcludeResultCode: "AWS082",
		},
		{
			name: "count is 1 from conditional",
			source: `
			variable "enabled" {
				default = true
			}
			resource "aws_default_vpc" "this" {
				count =  var.enabled ? 1 : 0
			}
`,
			mustIncludeResultCode: "AWS082",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanHCL(test.source, t)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}
}
