package rules

import (
	"fmt"

	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/severity"

	"github.com/aquasecurity/tfsec/pkg/provider"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/hclcontext"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

const AWSRDSRetentionPeriod = "AWS091"
const AWSRDSRetentionPeriodDescription = "RDS Cluster and RDS instance should have backup retention longer than default 1 day"
const AWSRDSRetentionPeriodImpact = "Potential loss of data and short opportunity for recovery"
const AWSRDSRetentionPeriodResolution = "Explicitly set the retention period to greater than the default"
const AWSRDSRetentionPeriodExplanation = `
RDS backup retention for clusters defaults to 1 day, this may not be enough to identify and respond to an issue. Backup retention periods should be set to a period that is a balance on cost and limiting risk.
`
const AWSRDSRetentionPeriodBadExample = `
resource "aws_db_instance" "bad_example" {
	allocated_storage    = 10
	engine               = "mysql"
	engine_version       = "5.7"
	instance_class       = "db.t3.micro"
	name                 = "mydb"
	username             = "foo"
	password             = "foobarbaz"
	parameter_group_name = "default.mysql5.7"
	skip_final_snapshot  = true
}

resource "aws_rds_cluster" "bad_example" {
	cluster_identifier      = "aurora-cluster-demo"
	engine                  = "aurora-mysql"
	engine_version          = "5.7.mysql_aurora.2.03.2"
	availability_zones      = ["us-west-2a", "us-west-2b", "us-west-2c"]
	database_name           = "mydb"
	master_username         = "foo"
	master_password         = "bar"
	preferred_backup_window = "07:00-09:00"
  }
`
const AWSRDSRetentionPeriodGoodExample = `
resource "aws_rds_cluster" "good_example" {
	cluster_identifier      = "aurora-cluster-demo"
	engine                  = "aurora-mysql"
	engine_version          = "5.7.mysql_aurora.2.03.2"
	availability_zones      = ["us-west-2a", "us-west-2b", "us-west-2c"]
	database_name           = "mydb"
	master_username         = "foo"
	master_password         = "bar"
	backup_retention_period = 5
	preferred_backup_window = "07:00-09:00"
  }

  resource "aws_db_instance" "good_example" {
	allocated_storage    = 10
	engine               = "mysql"
	engine_version       = "5.7"
	instance_class       = "db.t3.micro"
	name                 = "mydb"
	username             = "foo"
	password             = "foobarbaz"
	parameter_group_name = "default.mysql5.7"
	backup_retention_period = 5
	skip_final_snapshot  = true
}
`

func init() {
	scanner.RegisterCheckRule(rule.Rule{
		ID: AWSRDSRetentionPeriod,
		Documentation: rule.RuleDocumentation{
			Summary:     AWSRDSRetentionPeriodDescription,
			Explanation: AWSRDSRetentionPeriodExplanation,
			Impact:      AWSRDSRetentionPeriodImpact,
			Resolution:  AWSRDSRetentionPeriodResolution,
			BadExample:  AWSRDSRetentionPeriodBadExample,
			GoodExample: AWSRDSRetentionPeriodGoodExample,
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/rds_cluster#backup_retention_period",
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/db_instance#backup_retention_period",
				"https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_WorkingWithAutomatedBackups.html#USER_WorkingWithAutomatedBackups.BackupRetention",
			},
		},
		Provider:        provider.AWSProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_rds_cluster", "aws_db_instance"},
		DefaultSeverity: severity.Medium,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ *hclcontext.Context) {
			if resourceBlock.HasChild("replicate_source_db") {
				return
			}

			if resourceBlock.MissingChild("backup_retention_period") {
				set.Add(
					result.New(resourceBlock).
						WithDescription(fmt.Sprintf("Resource '%s' does not have backup retention explicitly set", resourceBlock.FullName())).
						WithRange(resourceBlock.Range()),
				)
				return
			}

			retentionAttr := resourceBlock.GetAttribute("backup_retention_period")
			if retentionAttr.LessThanOrEqualTo(1) {
				set.Add(
					result.New(resourceBlock).
						WithDescription(fmt.Sprintf("Resource '%s' has backup retention period set to a low value", resourceBlock.FullName())).
						WithRange(retentionAttr.Range()).
						WithAttributeAnnotation(retentionAttr),
				)
			}

		},
	})
}
