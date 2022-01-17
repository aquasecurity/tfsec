package rds

import (
	"github.com/aquasecurity/defsec/provider/aws/rds"
	"github.com/aquasecurity/defsec/types"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func Adapt(modules []block.Module) rds.RDS {
	return rds.RDS{
		Instances: getInstances(modules),
		Clusters:  getClusters(modules),
		Classic:   getClassic(modules),
	}
}

func getInstances(modules []block.Module) (instances []rds.Instance) {

	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_db_instance") {
			instances = append(instances, adaptInstance(resource, module))
		}
	}

	return instances
}

func getClusters(modules []block.Module) (clusters []rds.Cluster) {
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_rds_cluster") {
			clusters = append(clusters, adaptCluster(resource, module))
		}
	}

	return clusters
}

func getClassic(modules []block.Module) (classic rds.Classic) {

	var classicSecurityGroups []rds.DBSecurityGroup

	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_db_security_group", "aws_redshift_security_group", "aws_elasticache_security_group") {
			classicSecurityGroups = append(classicSecurityGroups, adaptClassicDBSecurityGroup(resource))
		}
	}

	classic.DBSecurityGroups = classicSecurityGroups
	return classic
}

func adaptClusterInstance(resource block.Block, module block.Module) rds.ClusterInstance {

	return rds.ClusterInstance{
		ClusterIdentifier: resource.GetAttribute("cluster_identfier").AsStringValueOrDefault("", resource),
		Instance:          adaptInstance(resource, module),
	}
}

func adaptClassicDBSecurityGroup(resource block.Block) rds.DBSecurityGroup {
	return rds.DBSecurityGroup{
		Metadata: *resource.GetMetadata(),
	}
}

func adaptInstance(resource block.Block, module block.Module) rds.Instance {
	replicaSource := resource.GetAttribute("replicate_source_db")
	replicaSourceValue := ""
	if replicaSource.IsNotNil() {
		if referenced, err := module.GetReferencedBlock(replicaSource, resource); err == nil {
			replicaSourceValue = referenced.ID()

		}
	}
	return rds.Instance{
		Metadata:                  *resource.GetMetadata(),
		BackupRetentionPeriodDays: resource.GetAttribute("backup_retention_period").AsIntValueOrDefault(0, resource),
		ReplicationSourceARN:      types.StringExplicit(replicaSourceValue, *resource.GetMetadata()),
		PerformanceInsights:       adaptPerformanceInsights(resource),
		Encryption:                adaptEncryption(resource),
		PublicAccess:              resource.GetAttribute("publicly_accessible").AsBoolValueOrDefault(false, resource),
	}
}

func adaptCluster(resource block.Block, module block.Module) rds.Cluster {

	return rds.Cluster{
		Metadata:                  *resource.GetMetadata(),
		BackupRetentionPeriodDays: resource.GetAttribute("backup_retention_period").AsIntValueOrDefault(0, resource),
		ReplicationSourceARN:      resource.GetAttribute("replicate_source_db").AsStringValueOrDefault("", resource),
		PerformanceInsights:       adaptPerformanceInsights(resource),
		Instances:                 getClusterInstances(resource, module),
		Encryption:                adaptEncryption(resource),
	}
}

func getClusterInstances(resource block.Block, module block.Module) (clusterInstances []rds.ClusterInstance) {
	clusterInstanceResources := module.GetReferencingResources(resource, "aws_rds_cluster_instance", "cluster_identifier")

	for _, ciResource := range clusterInstanceResources {
		clusterInstances = append(clusterInstances, adaptClusterInstance(ciResource, module))
	}
	return clusterInstances
}

func adaptPerformanceInsights(resource block.Block) rds.PerformanceInsights {
	return rds.PerformanceInsights{
		Enabled:  resource.GetAttribute("performance_insights_enabled").AsBoolValueOrDefault(false, resource),
		KMSKeyID: resource.GetAttribute("performance_insights_kms_key_id").AsStringValueOrDefault("", resource),
	}
}

func adaptEncryption(resource block.Block) rds.Encryption {
	return rds.Encryption{
		EncryptStorage: resource.GetAttribute("storage_encrypted").AsBoolValueOrDefault(false, resource),
		KMSKeyID:       resource.GetAttribute("kms_key_id").AsStringValueOrDefault("", resource),
	}
}
