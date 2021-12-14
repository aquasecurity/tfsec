package elbv2
 
 // generator-locked
 import (
 	"testing"
 
 	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
 )
 
 func Test_AWSNotInternal(t *testing.T) {
 	expectedCode := "aws-elbv2-alb-not-public"
 
 	var tests = []struct {
 		name                  string
 		source                string
 		mustIncludeResultCode string
 		mustExcludeResultCode string
 	}{
 		{
 			name: "check aws_alb when not internal",
 			source: `
 resource "aws_alb" "my-resource" {
 	internal = false
 }`,
 			mustIncludeResultCode: expectedCode,
 		},
 		{
 			name: "check aws_elb when not internal",
 			source: `
 resource "aws_elb" "my-resource" {
 	internal = false
 }`,
 			mustIncludeResultCode: expectedCode,
 		},
 		{
 			name: "check aws_lb when not internal",
 			source: `
 resource "aws_lb" "my-resource" {
 	internal = false
 }`,
 			mustIncludeResultCode: expectedCode,
 		},
 		{
 			name: "check aws_lb when not explicitly marked as internal",
 			source: `
 resource "aws_lb" "my-resource" {
 }`,
 			mustIncludeResultCode: expectedCode,
 		},
 		{
 			name: "check aws_lb when explicitly marked as internal",
 			source: `
 resource "aws_lb" "my-resource" {
 	internal = true
 }`,
 			mustExcludeResultCode: expectedCode,
 		},
 		{
 			name: "check aws_lb when explicitly is a gateway",
 			source: `
 resource "aws_lb" "gwlb" {
 	name               = var.gwlb_name
 	load_balancer_type = "gateway"
 	subnets            = local.appliance_subnets_id
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
