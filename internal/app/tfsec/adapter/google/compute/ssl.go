package compute

import (
	"github.com/aquasecurity/defsec/provider/google/compute"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func adaptSSLPolicies(modules block.Modules) (policies []compute.SSLPolicy) {
	for _, policyBlock := range modules.GetResourcesByType("google_compute_ssl_policy") {
		var policy compute.SSLPolicy
		policy.Metadata = policyBlock.Metadata()
		policy.Name = policyBlock.GetAttribute("name").AsStringValueOrDefault("", policyBlock)
		policy.Profile = policyBlock.GetAttribute("profile").AsStringValueOrDefault("", policyBlock)
		policy.MinimumTLSVersion = policyBlock.GetAttribute("min_tls_version").AsStringValueOrDefault("TLS_1_0", policyBlock)
		policies = append(policies, policy)
	}
	return policies
}
