package codebuild

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckEnableEncryption = rules.Register(
	rules.Rule{
		AVDID:       "AVD-AWS-0018",
		Provider:    provider.AWSProvider,
		Service:     "codebuild",
		ShortCode:   "enable-encryption",
		Summary:     "CodeBuild Project artifacts encryption should not be disabled",
		Impact:      "CodeBuild project artifacts are unencrypted",
		Resolution:  "Enable encryption for CodeBuild project artifacts",
		Explanation: `All artifacts produced by your CodeBuild project pipeline should always be encrypted`,
		Links: []string{
			"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-codebuild-project-artifacts.html",
			"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-codebuild-project.html",
		},
		Severity: severity.High,
	},
	func(s *state.State) (results rules.Results) {
		for _, project := range s.AWS.CodeBuild.Projects {
			if project.ArtifactSettings.EncryptionEnabled.IsFalse() {
				results.Add(
					"Encryption is not enabled for project artifacts.",
					&project,
					project.ArtifactSettings.EncryptionEnabled,
				)
			} else {
				results.AddPassed(&project)
			}

			for _, setting := range project.SecondaryArtifactSettings {
				if setting.EncryptionEnabled.IsFalse() {
					results.Add(
						"Encryption is not enabled for secondary project artifacts.",
						&setting,
						setting.EncryptionEnabled,
					)
				} else {
					results.AddPassed(&setting)
				}
			}

		}
		return
	},
)
