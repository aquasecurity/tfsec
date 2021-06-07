package rules

import (
	"fmt"

	"github.com/tfsec/tfsec/pkg/result"
	"github.com/tfsec/tfsec/pkg/severity"

	"github.com/tfsec/tfsec/pkg/provider"

	"github.com/tfsec/tfsec/internal/app/tfsec/hclcontext"

	"github.com/tfsec/tfsec/internal/app/tfsec/block"

	"github.com/tfsec/tfsec/pkg/rule"

	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

const AWSEKSHasControlPlaneLoggingEnabled = "AWS067"
const AWSEKSHasControlPlaneLoggingEnabledDescription = "EKS Clusters should have cluster control plane logging turned on"
const AWSEKSHasControlPlaneLoggingEnabledImpact = "Logging provides valuable information about access and usage"
const AWSEKSHasControlPlaneLoggingEnabledResolution = "Enable logging for the EKS control plane"
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
	scanner.RegisterCheckRule(rule.Rule{
		ID: AWSEKSHasControlPlaneLoggingEnabled,
		Documentation: rule.RuleDocumentation{
			Summary:     AWSEKSHasControlPlaneLoggingEnabledDescription,
			Impact:      AWSEKSHasControlPlaneLoggingEnabledImpact,
			Resolution:  AWSEKSHasControlPlaneLoggingEnabledResolution,
			Explanation: AWSEKSHasControlPlaneLoggingEnabledExplanation,
			BadExample:  AWSEKSHasControlPlaneLoggingEnabledBadExample,
			GoodExample: AWSEKSHasControlPlaneLoggingEnabledGoodExample,
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/eks_cluster#enabled_cluster_log_types",
				"https://docs.aws.amazon.com/eks/latest/userguide/control-plane-logs.html",
			},
		},
		Provider:       provider.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_eks_cluster"},
		CheckFunc: func(set result.Set, block *block.Block, _ *hclcontext.Context) {

			controlPlaneLogging := []string{"api", "audit", "authenticator", "controllerManager", "scheduler"}

			if block.MissingChild("enabled_cluster_log_types") {
				set.Add(
					result.New().
						WithDescription(fmt.Sprintf("Resource '%s' missing the enabled_cluster_log_types attribute to enable control plane logging", block.FullName())).
						WithRange(block.Range()).
						WithSeverity(severity.Error),
				)
				return
			}

			configuredLoggingAttr := block.GetAttribute("enabled_cluster_log_types")
			for _, logType := range controlPlaneLogging {
				if !configuredLoggingAttr.Contains(logType) {
					set.Add(
						result.New().
							WithDescription(fmt.Sprintf("Resource '%s' is missing the control plane log type '%s'", block.FullName(), logType)).
							WithRange(configuredLoggingAttr.Range()).
							WithAttributeAnnotation(configuredLoggingAttr).
							WithSeverity(severity.Error),
					)
				}
			}
		},
	})
}
