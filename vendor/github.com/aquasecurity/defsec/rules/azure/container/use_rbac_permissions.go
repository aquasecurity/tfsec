package container

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckUseRbacPermissions = rules.Register(
	rules.Rule{
		Provider:    provider.AzureProvider,
		Service:     "container",
		ShortCode:   "use-rbac-permissions",
		Summary:     "Ensure RBAC is enabled on AKS clusters",
		Impact:      "No role based access control is in place for the AKS cluster",
		Resolution:  "Enable RBAC",
		Explanation: `Using Kubernetes role-based access control (RBAC), you can grant users, groups, and service accounts access to only the resources they need.`,
		Links: []string{
			"https://docs.microsoft.com/en-us/azure/aks/concepts-identity",
		},
		Severity: severity.High,
	},
	func(s *state.State) (results rules.Results) {
		for _, cluster := range s.Azure.Container.KubernetesClusters {
			if cluster.RoleBasedAccessControl.Enabled.IsFalse() {
				results.Add(
					"Cluster has RBAC disabled",
					cluster.RoleBasedAccessControl.Enabled,
				)
			}
		}
		return
	},
)
