package lambda

import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
)

func Test_AWSCheckLambdaFunctionForSourceARN(t *testing.T) {
	expectedCode := "aws-lambda-restrict-source-arn"

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "Principal present with no source_arn",
			source: `
 resource "aws_lambda_permission" "with_sns" {
   statement_id  = "AllowExecutionFromSNS"
   action        = "lambda:InvokeFunction"
   function_name = aws_lambda_function.func.function_name
   principal     = "sns.amazonaws.com"
 }
 `,
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "Principal present and source_arn present",
			source: `
 resource "aws_lambda_permission" "with_sns" {
   statement_id  = "AllowExecutionFromSNS"
   action        = "lambda:InvokeFunction"
   function_name = aws_lambda_function.func.function_name
   principal     = "sns.amazonaws.com"
   source_arn    = aws_sns_topic.default.arn
 }
 `,
			mustExcludeResultCode: expectedCode,
		},
		{
			name: "No principal specified",
			source: `
 resource "aws_lambda_permission" "with_sns" {
   statement_id  = "AllowExecutionFromSNS"
   action        = "lambda:InvokeFunction"
   function_name = aws_lambda_function.func.function_name
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
