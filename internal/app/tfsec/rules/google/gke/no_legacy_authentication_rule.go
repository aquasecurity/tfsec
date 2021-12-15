package gke

import (
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
)

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		LegacyID: "GCP008",
		BadExample: []string{`
 resource "google_container_cluster" "bad_example" {
 }
 
 resource "google_container_cluster" "gke" {
 	master_auth {
 	    username = ""
 	    password = ""
 		client_certificate_config {
 			issue_client_certificate = true
 	    }
 	}
 }
 `},
		GoodExample: []string{`
 resource "google_container_cluster" "good_example" {
 	master_auth {
 	    username = ""
 	    password = ""
 	}
 }
 `},
		Links: []string{
			"https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/container_cluster#master_auth",
			"https://cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster#restrict_authn_methods",
		},
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"google_container_cluster"},
		CheckTerraform: func(resourceBlock block.Block, _ block.Module) (results rules.Results) {

			if resourceBlock.MissingChild("master_auth") {
				results.Add("Resource does not disable basic auth with static passwords for client authentication. Disable this with a master_auth block container empty strings for user and password.", resourceBlock)
				return
			}

			staticAuthPass := resourceBlock.GetNestedAttribute("master_auth.password")
			if staticAuthPass.IsNotNil() && !staticAuthPass.IsEmpty() {
				results.Add("Resource defines a cluster using basic auth with static passwords for client authentication. It is recommended to use OAuth or service accounts instead.", staticAuthPass)
			}

			if resourceBlock.MissingNestedChild("master_auth.client_certificate_config") {
				return
			}

			issueClientCert := resourceBlock.GetNestedAttribute("master_auth.client_certificate_config.issue_client_certificate")
			if issueClientCert.IsNil() {
				return
			}
			if issueClientCert.IsTrue() {
				results.Add("Resource defines a cluster using basic auth with client certificates for authentication. This cert has no permissions if RBAC is enabled and ABAC is disabled. It is recommended to use OAuth or service accounts instead.", issueClientCert)
			}

			return results
		},
	})
}
