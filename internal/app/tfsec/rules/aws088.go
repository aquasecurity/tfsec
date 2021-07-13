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

const AWSRedisClusterBackupRetention = "AWS088"
const AWSRedisClusterBackupRetentionDescription = "Redis cluster should have backup retention turned on"
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
	scanner.RegisterCheckRule(rule.Rule{
		ID: AWSRedisClusterBackupRetention,
		Documentation: rule.RuleDocumentation{
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
		Provider:        provider.AWSProvider,
		RequiredTypes:   []string{"resource"},
		RequiredLabels:  []string{"aws_elasticache_cluster"},
		DefaultSeverity: severity.Medium,
		CheckFunc: func(set result.Set, resourceBlock block.Block, _ *hclcontext.Context) {

			engineAttr := resourceBlock.GetAttribute("engine")
			if engineAttr != nil && engineAttr.Equals("redis", block.IgnoreCase) {
				nodeTypeAttr := resourceBlock.GetAttribute("node_type")
				if nodeTypeAttr != nil && !nodeTypeAttr.Equals("cache.t1.micro") {
					snapshotRetentionAttr := resourceBlock.GetAttribute("snapshot_retention_limit")
					if snapshotRetentionAttr == nil {
						set.Add(
							result.New(resourceBlock).
								WithDescription(fmt.Sprintf("Resource '%s' should have snapshot retention specified", resourceBlock.FullName())).
								WithRange(resourceBlock.Range()),
						)
						return
					}

					if snapshotRetentionAttr.Equals(0) {
						set.Add(
							result.New(resourceBlock).
								WithDescription(fmt.Sprintf("Resource '%s' has snapshot retention set to 0", resourceBlock.FullName())).
								WithRange(snapshotRetentionAttr.Range()).
								WithAttributeAnnotation(snapshotRetentionAttr),
						)
					}
				}
			}

		},
	})
}
