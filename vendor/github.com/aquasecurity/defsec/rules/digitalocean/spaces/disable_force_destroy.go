package spaces

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckDisableForceDestroy = rules.Register(
	rules.Rule{
                AVDID: "AVD-DIG-0005",
		Provider:    provider.DigitalOceanProvider,
		Service:     "spaces",
		ShortCode:   "disable-force-destroy",
		Summary:     "Force destroy is enabled on Spaces bucket which is dangerous",
		Impact:      "Accidental deletion of bucket objects",
		Resolution:  "Don't use force destroy on bucket configuration",
		Explanation: `Enabling force destroy on a Spaces bucket means that the bucket can be deleted without the additional check that it is empty. This risks important data being accidentally deleted by a bucket removal process.`,
		Links:       []string{},
		Severity:    severity.Medium,
	},
	func(s *state.State) (results rules.Results) {
		for _, bucket := range s.DigitalOcean.Spaces.Buckets {
			if bucket.ForceDestroy.IsTrue() {
				results.Add(
					"Bucket has force-destroy enabled.",
					bucket.ForceDestroy,
				)
			}
		}
		return
	},
)
