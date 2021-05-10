package checks

import (
	"fmt"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

const AWSRedisClusterBackupRetention scanner.RuleCode = "AWS088"
const AWSRedisClusterBackupRetentionDescription scanner.RuleSummary = "Redis cluster should be backup retention turned on"
const AWSRedisClusterBackupRetentionImpact = "Without backups of the redis cluster recovery is made difficult"
const AWSRedisClusterBackupRetentionResolution = "Configure snapshot retention for redis cluster"
const AWSRedisClusterBackupRetentionExplanation = `
Redis clusters should have a snapshot retention time to ensure that they are backed up and can be restored if required.
`
const AWSRedisClusterBackupRetentionBadExample = `
resource "aws_elasticache_cluster" "bad_example" {
	cluster_id           = "cluster-example"
	engine               = "redis"
	node_type            = "cache.m4.large"
	num_cache_nodes      = 1
	parameter_group_name = "default.redis3.2"
	engine_version       = "3.2.10"
	port                 = 6379
}
`
const AWSRedisClusterBackupRetentionGoodExample = `
resource "aws_elasticache_cluster" "good_example" {
	cluster_id           = "cluster-example"
	engine               = "redis"
	node_type            = "cache.m4.large"
	num_cache_nodes      = 1
	parameter_group_name = "default.redis3.2"
	engine_version       = "3.2.10"
	port                 = 6379

	snapshot_retention_limit = 5
}
`

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code: AWSRedisClusterBackupRetention,
		Documentation: scanner.CheckDocumentation{
			Summary:     AWSRedisClusterBackupRetentionDescription,
			Explanation: AWSRedisClusterBackupRetentionExplanation,
			Impact:      AWSRedisClusterBackupRetentionImpact,
			Resolution:  AWSRedisClusterBackupRetentionResolution,
			BadExample:  AWSRedisClusterBackupRetentionBadExample,
			GoodExample: AWSRedisClusterBackupRetentionGoodExample,
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/elasticache_cluster#snapshot_retention_limit",
				"https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/backups-automatic.html",
			},
		},
		Provider:       scanner.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_elasticache_cluster"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {

			engineAttr := block.GetAttribute("engine")
			if engineAttr.Equals("redis", parser.IgnoreCase) && !block.GetAttribute("node_type").Equals("cache.t1.micro") {
				snapshotRetention := block.GetAttribute("snapshot_retention_limit")
				if snapshotRetention == nil {
					return []scanner.Result{
						check.NewResult(
							fmt.Sprintf("Resource '%s' should have snapshot retention specified", block.FullName()),
							block.Range(),
							scanner.SeverityWarning,
						),
					}
				}

				if snapshotRetention.Equals(0) {
					return []scanner.Result{
						check.NewResultWithValueAnnotation(
							fmt.Sprintf("Resource '%s' has snapshot retention set to 0", block.FullName()),
							snapshotRetention.Range(),
							snapshotRetention,
							scanner.SeverityWarning,
						),
					}
				}
			}

			return nil
		},
	})
}
