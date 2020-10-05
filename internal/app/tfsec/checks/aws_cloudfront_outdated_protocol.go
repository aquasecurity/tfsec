package checks

import (
	"fmt"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
	"github.com/zclconf/go-cty/cty"
)

// AWSCloudFrontOutdatedProtocol See https://github.com/tfsec/tfsec#included-checks for check info
const AWSCloudFrontOutdatedProtocol scanner.RuleID = "AWS021"
const AWSCloudFrontOutdatedProtocolDescription scanner.RuleDescription = "CloudFront distribution uses outdated SSL/TSL protocols."

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code:           AWSCloudFrontOutdatedProtocol,
		Description:    AWSCloudFrontOutdatedProtocolDescription,
		Provider:       scanner.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_cloudfront_distribution"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, context *scanner.Context) []scanner.Result {

			viewerCertificateBlock := block.GetBlock("viewer_certificate")
			if viewerCertificateBlock == nil {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' defines outdated SSL/TLS policies (missing viewer_certificate block)", block.Name()),
						viewerCertificateBlock.Range(),
						scanner.SeverityError,
					),
				}
			}

			if minVersion := viewerCertificateBlock.GetAttribute("minimum_protocol_version"); minVersion == nil {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' defines outdated SSL/TLS policies (missing minimum_protocol_version attribute)", block.Name()),
						viewerCertificateBlock.Range(),
						scanner.SeverityError,
					),
				}
			} else if minVersion.Type() == cty.String && minVersion.Value().AsString() != "TLSv1.2_2019" {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' defines outdated SSL/TLS policies (not using TLSv1.2_2019)", block.Name()),
						minVersion.Range(),
						scanner.SeverityError,
					),
				}
			}
			return nil
		},
	})
}
