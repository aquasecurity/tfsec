package athena

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/provider/aws/athena"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckEnableAtRestEncryption = rules.Register(
	rules.Rule{
		AVDID:       "AVD-AWS-0006",
		Provider:    provider.AWSProvider,
		Service:     "athena",
		ShortCode:   "enable-at-rest-encryption",
		Summary:     "Athena databases and workgroup configurations are created unencrypted at rest by default, they should be encrypted",
		Impact:      "Data can be read if the Athena Database is compromised",
		Resolution:  "Enable encryption at rest for Athena databases and workgroup configurations",
		Explanation: `Athena databases and workspace result sets should be encrypted at rests. These databases and query sets are generally derived from data in S3 buckets and should have the same level of at rest protection.`,
		Links: []string{
			"https://docs.aws.amazon.com/athena/latest/ug/encryption.html",
		},
		Severity: severity.High,
	},
	func(s *state.State) (results rules.Results) {
		for _, workgroup := range s.AWS.Athena.Workgroups {
			if !workgroup.IsManaged() {
				continue
			}
			if workgroup.Encryption.Type.EqualTo(athena.EncryptionTypeNone) {
				results.Add(
					"Workgroup does not have encryption configured.",
					&workgroup,
					workgroup.Encryption.Type,
				)
			} else {
				results.AddPassed(&workgroup)
			}
		}
		for _, database := range s.AWS.Athena.Databases {
			if !database.IsManaged() {
				continue
			}
			if database.Encryption.Type.EqualTo(athena.EncryptionTypeNone) {
				results.Add(
					"Database does not have encryption configured.",
					&database,
					database.Encryption.Type,
				)
			} else {
				results.AddPassed(&database)
			}
		}
		return
	},
)
