package rds

import (
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckBackupRetentionSpecified = rules.Register(
	rules.Rule{
		AVDID:       "AVD-AWS-0077",
		Provider:    provider.AWSProvider,
		Service:     "rds",
		ShortCode:   "specify-backup-retention",
		Summary:     "RDS Cluster and RDS instance should have backup retention longer than default 1 day",
		Impact:      "Potential loss of data and short opportunity for recovery",
		Resolution:  "Explicitly set the retention period to greater than the default",
		Explanation: `RDS backup retention for clusters defaults to 1 day, this may not be enough to identify and respond to an issue. Backup retention periods should be set to a period that is a balance on cost and limiting risk.`,
		Links: []string{
			"https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_WorkingWithAutomatedBackups.html#USER_WorkingWithAutomatedBackups.BackupRetention",
		},
		Severity: severity.Medium,
	},
	func(s *state.State) (results rules.Results) {
		for _, cluster := range s.AWS.RDS.Clusters {
			if !cluster.ReplicationSourceARN.IsEmpty() {
				continue
			}
			if !cluster.IsManaged() {
				continue
			}
			if cluster.BackupRetentionPeriodDays.LessThan(2) {
				results.Add(
					"Cluster has very low backup retention period.",
					&cluster,
					cluster.BackupRetentionPeriodDays,
				)
			} else {
				results.AddPassed(&cluster)
			}
		}
		for _, instance := range s.AWS.RDS.Instances {
			if !instance.IsManaged() {
				continue
			}
			if instance.BackupRetentionPeriodDays.LessThan(2) {
				results.Add(
					"Instance has very low backup retention period.",
					&instance,
					instance.BackupRetentionPeriodDays,
				)
			} else {
				results.AddPassed(&instance)
			}
		}

		return
	},
)
