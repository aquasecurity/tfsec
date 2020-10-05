package checks

import (
	"fmt"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"

	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"

	"github.com/zclconf/go-cty/cty"
)

// GkeLegacyAuthEnabled See https://github.com/tfsec/tfsec#included-checks for check info
const GkeLegacyAuthEnabled scanner.RuleID = "GCP008"
const GkeLegacyAuthEnabledDescription scanner.RuleDescription = "Legacy client authentication methods utilized."

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code:           GkeLegacyAuthEnabled,
		Description:    GkeLegacyAuthEnabledDescription,
		Provider:       scanner.GCPProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"google_container_cluster"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {

			masterAuthBlock := block.GetBlock("master_auth")
			staticAuthUser := masterAuthBlock.GetAttribute("username")
			staticAuthPass := masterAuthBlock.GetAttribute("password")
			if masterAuthBlock == nil {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' does not disable basic auth with static passwords for client authentication. Disable this with a master_auth block container empty strings for user and password. https://cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster#restrict_authn_methods", block.Name()),
						block.Range(),
						scanner.SeverityError,
					),
				}
			} else if staticAuthUser.Type() == cty.String && staticAuthUser.Value().AsString() != "" && staticAuthPass.Type() == cty.String && staticAuthPass.Value().AsString() != "" {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' defines a cluster using basic auth with static passwords for client authentication. It is recommended to use OAuth or service accounts instead. https://cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster#restrict_authn_methods", block.Name()),
						masterAuthBlock.Range(),
						scanner.SeverityError,
					),
				}
			}
			issueClientCert := masterAuthBlock.GetBlock("client_certificate_config").GetAttribute("issue_client_certificate")
			if issueClientCert.Type() == cty.Bool && issueClientCert.Value().True() || issueClientCert.Type() == cty.String && issueClientCert.Value().AsString() == "true" {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' defines a cluster using basic auth with client certificates for authentication. This cert has no permissions if RBAC is enabled and ABAC is disabled. It is recommended to use OAuth or service accounts instead. https://cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster#restrict_authn_methods", block.Name()),
						issueClientCert.Range(),
						scanner.SeverityError,
					),
				}
			}

			return nil
		},
	})
}
