package elb

import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
)

func Test_AWSALBDropsInvalidHeaders(t *testing.T) {
	expectedCode := "aws-elb-drop-invalid-headers"

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "Alb that doesn't drop invalid headers by default fails",
			source: `
resource "aws_alb" "bad_example" {
	name               = "bad_alb"
	internal           = false
	load_balancer_type = "application"
	
  }
`,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "lb that doesn't drop invalid headers by default fails",
			source: `
resource "aws_lb" "bad_example" {
	name               = "bad_alb"
	internal           = false
	load_balancer_type = "application"
	
	access_logs {
	  bucket  = aws_s3_bucket.lb_logs.bucket
	  prefix  = "test-lb"
	  enabled = true
	}
  }
`,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "Alb that doesn't drop invalid headers explicitly fails",
			source: `
resource "aws_alb" "bad_example" {
	name               = "bad_alb"
	internal           = false
	load_balancer_type = "application"
	
	drop_invalid_header_fields = false
  }
`,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "lb that doesn't drop invalid headers fails",
			source: `
resource "aws_lb" "bad_example" {
	name               = "bad_alb"
	internal           = false
	load_balancer_type = "application"
  
	drop_invalid_header_fields = false
  }
`,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "ALB that drops invalid headers passes check",
			source: `
resource "aws_alb" "good_example" {
	name               = "good_alb"
	internal           = false
	load_balancer_type = "application"
	
	drop_invalid_header_fields = true
  }
`,
			mustExcludeResultCode: expectedCode,
		},
		{
			name: "LB that drops invalid headers passes check",
			source: `
resource "aws_lb" "good_example" {
	name               = "good_alb"
	internal           = false
	load_balancer_type = "application"

	drop_invalid_header_fields = true
  }
`,
			mustExcludeResultCode: expectedCode,
		},
		{
			name: "Network LB passes check as not applicablt",
			source: `
resource "aws_lb" "good_example" {
	name               = "good_alb"
	internal           = false
	load_balancer_type = "network"
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
