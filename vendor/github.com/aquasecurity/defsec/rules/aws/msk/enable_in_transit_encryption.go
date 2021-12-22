package msk

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/provider/aws/msk"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckEnableInTransitEncryption = rules.Register(
	rules.Rule{
		AVDID:       "AVD-AWS-0073",
		Provider:    provider.AWSProvider,
		Service:     "msk",
		ShortCode:   "enable-in-transit-encryption",
		Summary:     "A MSK cluster allows unencrypted data in transit.",
		Impact:      "Intercepted data can be read in transit",
		Resolution:  "Enable in transit encryption",
		Explanation: `Encryption should be forced for Kafka clusters, including for communication between nodes. This ensure sensitive data is kept private.`,
		Links: []string{
			"https://docs.aws.amazon.com/msk/latest/developerguide/msk-encryption.html",
		},
		Severity: severity.High,
	},
	func(s *state.State) (results rules.Results) {
		for _, cluster := range s.AWS.MSK.Clusters {
			if cluster.EncryptionInTransit.ClientBroker.EqualTo(msk.ClientBrokerEncryptionPlaintext) {
				results.Add(
					"Cluster allows plaintext communication.",
					&cluster,
					cluster.EncryptionInTransit.ClientBroker,
				)
			} else if cluster.EncryptionInTransit.ClientBroker.EqualTo(msk.ClientBrokerEncryptionTLSOrPlaintext) {
				results.Add(
					"Cluster allows plaintext communication.",
					&cluster,
					cluster.EncryptionInTransit.ClientBroker,
				)
			} else {
				results.AddPassed(&cluster)
			}

		}
		return
	},
)
