package checks

import (
	"fmt"

	"github.com/zclconf/go-cty/cty"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

const AWSCloudFrontOutdatedProtocol scanner.RuleCode = "AWS021"
const AWSCloudFrontOutdatedProtocolDescription scanner.RuleSummary = "CloudFront distribution uses outdated SSL/TLS protocols."
const AWSCloudFrontOutdatedProtocolExplanation = `
You should not use outdated/insecure TLS versions for encryption. You should be using TLS v1.2+.
`
const AWSCloudFrontOutdatedProtocolBadExample = `
resource "aws_cloudfront_distribution" "s3_distribution" {
  viewer_certificate {
    cloudfront_default_certificate = true
	minimum_protocol_version = "TLSv1.0"
  }
}
`
const AWSCloudFrontOutdatedProtocolGoodExample = `
resource "aws_cloudfront_distribution" "s3_distribution" {
  viewer_certificate {
    cloudfront_default_certificate = true
	minimum_protocol_version = "TLSv1.2_2019"
  }
}
`

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code: AWSCloudFrontOutdatedProtocol,
		Documentation: scanner.CheckDocumentation{
			Summary:     AWSCloudFrontOutdatedProtocolDescription,
			Explanation: AWSCloudFrontOutdatedProtocolExplanation,
			BadExample:  AWSCloudFrontOutdatedProtocolBadExample,
			GoodExample: AWSCloudFrontOutdatedProtocolGoodExample,
			Links:       []string{},
		},
		Provider:       scanner.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_cloudfront_distribution"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, context *scanner.Context) []scanner.Result {

			viewerCertificateBlock := block.GetBlock("viewer_certificate")
			if viewerCertificateBlock == nil {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' defines outdated SSL/TLS policies (missing viewer_certificate block)", block.FullName()),
						viewerCertificateBlock.Range(),
						scanner.SeverityError,
					),
				}
			}

			if minVersion := viewerCertificateBlock.GetAttribute("minimum_protocol_version"); minVersion == nil {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' defines outdated SSL/TLS policies (missing minimum_protocol_version attribute)", block.FullName()),
						viewerCertificateBlock.Range(),
						scanner.SeverityError,
					),
				}
			} else if minVersion.Type() == cty.String && minVersion.Value().AsString() != "TLSv1.2_2019" {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' defines outdated SSL/TLS policies (not using TLSv1.2_2019)", block.FullName()),
						minVersion.Range(),
						scanner.SeverityError,
					),
				}
			}
			return nil
		},
	})
}
