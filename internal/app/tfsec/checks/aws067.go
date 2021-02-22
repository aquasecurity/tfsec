package checks

import (
	"fmt"
	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

const AWSEKSHasControlPlaneLoggingEnabled scanner.RuleCode = "AWS067"
const AWSEKSHasControlPlaneLoggingEnabledDescription scanner.RuleSummary = "EKS Clusters should have cluster control plane logging turned on"
const AWSEKSHasControlPlaneLoggingEnabledExplanation = `
By default cluster control plane logging is not turned on. Logging is available for audit, api, authenticator, controllerManager and scheduler. All logging should be turned on for cluster control plane.
`
const AWSEKSHasControlPlaneLoggingEnabledBadExample = `
resource "aws_eks_cluster" "bad_example" {
    encryption_config {
        resources = [ "secrets" ]
        provider {
            key_arn = var.kms_arn
        }
    }

    name = "bad_example_cluster"
    role_arn = var.cluster_arn
    vpc_config {
        endpoint_public_access = false
    }
}
`
const AWSEKSHasControlPlaneLoggingEnabledGoodExample = `
resource "aws_eks_cluster" "good_example" {
    encryption_config {
        resources = [ "secrets" ]
        provider {
            key_arn = var.kms_arn
        }
    }

	enabled_cluster_log_types = ["api", "authenticator", "audit", "scheduler", "controllerManager"]

    name = "good_example_cluster"
    role_arn = var.cluster_arn
    vpc_config {
        endpoint_public_access = false
    }
}
`

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code: AWSEKSHasControlPlaneLoggingEnabled,
		Documentation: scanner.CheckDocumentation{
			Summary:     AWSEKSHasControlPlaneLoggingEnabledDescription,
			Explanation: AWSEKSHasControlPlaneLoggingEnabledExplanation,
			BadExample:  AWSEKSHasControlPlaneLoggingEnabledBadExample,
			GoodExample: AWSEKSHasControlPlaneLoggingEnabledGoodExample,
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/eks_cluster#enabled_cluster_log_types",
				"https://docs.aws.amazon.com/eks/latest/userguide/control-plane-logs.html",
			},
		},
		Provider:       scanner.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_eks_cluster"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {

			controlPlaneLogging := []string{"api", "audit", "authenticator", "controllerManager", "scheduler"}

			if block.MissingChild("enabled_cluster_log_types") {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' missing the enabled_cluster_log_types attribute to enable control plane logging", block.FullName()),
						block.Range(),
						scanner.SeverityError,
						),
				}
			}

			configuredLogging := block.GetAttribute("enabled_cluster_log_types")
			var logTypeResults []scanner.Result
			for _, logType := range controlPlaneLogging {
				if ! configuredLogging.Contains(logType) {
					logTypeResults = append(logTypeResults, check.NewResultWithValueAnnotation(
						fmt.Sprintf("Resource '%s' is missing the control plane log type '%s'", block.FullName(), logType),
						configuredLogging.Range(),
						configuredLogging,
						scanner.SeverityError,
						))
				}
			}

			return logTypeResults
		},
	})
}
