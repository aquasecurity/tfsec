package sam

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckEnableApiCacheEncryption = rules.Register(
	rules.Rule{
		AVDID:       "AVD-AWS-0110",
		Provider:    provider.AWSProvider,
		Service:     "sam",
		ShortCode:   "enable-api-cache-encryption",
		Summary:     "SAM API must have data cache enabled",
		Impact:      "Data stored in the cache that is unencrypted may be vulnerable to compromise",
		Resolution:  "Enable cache encryption",
		Explanation: `Method cache encryption ensures that any sensitive data in the cache is not vulnerable to compromise in the event of interception`,
		Links: []string{
			"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-apigateway-stage-methodsetting.html#cfn-apigateway-stage-methodsetting-cachedataencrypted",
		},
		CloudFormation: &rules.EngineMetadata{
			GoodExamples:        cloudFormationEnableApiCacheEncryptionGoodExamples,
			BadExamples:         cloudFormationEnableApiCacheEncryptionBadExamples,
			Links:               cloudFormationEnableApiCacheEncryptionLinks,
			RemediationMarkdown: cloudFormationEnableApiCacheEncryptionRemediationMarkdown,
		},
		Severity: severity.Medium,
	},
	func(s *state.State) (results rules.Results) {
		for _, api := range s.AWS.SAM.APIs {
			if api.IsUnmanaged() {
				continue
			}

			if api.RESTMethodSettings.CacheDataEncrypted.IsFalse() {
				results.Add(
					"Cache data is not encrypted.",
					api.RESTMethodSettings.CacheDataEncrypted,
				)
			} else {
				results.AddPassed(&api)
			}
		}
		return
	},
)
