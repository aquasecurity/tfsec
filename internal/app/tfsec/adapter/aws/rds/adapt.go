package rds

import (
	"github.com/aquasecurity/defsec/provider/aws/rds"
	"github.com/aquasecurity/defsec/types"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func Adapt(modules block.Modules) rds.RDS {
	return rds.RDS{
		Instances: getInstances(modules),
		Clusters:  getClusters(modules),
		Classic:   getClassic(modules),
	}
}

func getInstances(modules block.Modules) (instances []rds.Instance) {
	for _, resource := range modules.GetResourcesByType("aws_db_instance") {
		instances = append(instances, adaptInstance(resource, modules))
	}

	return instances
}

func getClusters(modules block.Modules) (clusters []rds.Cluster) {

	rdsInstanceMaps := modules.GetChildResourceIDMapByType("aws_rds_cluster_instance")
	for _, resource := range modules.GetResourcesByType("aws_rds_cluster") {
		cluster, instanceIDs := adaptCluster(resource, modules)
		for _, id := range instanceIDs {
			rdsInstanceMaps[id] = true
		}
		clusters = append(clusters, cluster)
	}

	var orphansID []string
	for id, resolved := range rdsInstanceMaps {
		if !resolved {
			orphansID = append(orphansID, id)
		}
	}

	orphanResources := modules.GetResourceByIDs(orphansID...)

	if len(orphanResources) > 0 {
		orphanCluster := rds.Cluster{
			Metadata: types.NewUnmanagedMetadata(),
		}
		for _, orphan := range orphanResources {
			orphanCluster.Instances = append(orphanCluster.Instances, adaptClusterInstance(orphan, modules))
		}
		clusters = append(clusters, orphanCluster)
	}

	return clusters
}

func getClassic(modules block.Modules) (classic rds.Classic) {

	var classicSecurityGroups []rds.DBSecurityGroup

	for _, resource := range modules.GetResourcesByType("aws_db_security_group", "aws_redshift_security_group", "aws_elasticache_security_group") {
		classicSecurityGroups = append(classicSecurityGroups, adaptClassicDBSecurityGroup(resource))
	}

	classic.DBSecurityGroups = classicSecurityGroups
	return classic
}

func adaptClusterInstance(resource block.Block, modules block.Modules) rds.ClusterInstance {

	return rds.ClusterInstance{
		Metadata:          resource.Metadata(),
		ClusterIdentifier: resource.GetAttribute("cluster_identfier").AsStringValueOrDefault("", resource),
		Instance:          adaptInstance(resource, modules),
	}
}

func adaptClassicDBSecurityGroup(resource block.Block) rds.DBSecurityGroup {
	return rds.DBSecurityGroup{
		Metadata: *resource.GetMetadata(),
	}
}

func adaptInstance(resource block.Block, modules block.Modules) rds.Instance {
	replicaSource := resource.GetAttribute("replicate_source_db")
	replicaSourceValue := ""
	if replicaSource.IsNotNil() {
		if referenced, err := modules.GetReferencedBlock(replicaSource, resource); err == nil {
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

func adaptCluster(resource block.Block, modules block.Modules) (rds.Cluster, []string) {

	clusterInstances, ids := getClusterInstances(resource, modules)

	return rds.Cluster{
		Metadata:                  *resource.GetMetadata(),
		BackupRetentionPeriodDays: resource.GetAttribute("backup_retention_period").AsIntValueOrDefault(0, resource),
		ReplicationSourceARN:      resource.GetAttribute("replicate_source_db").AsStringValueOrDefault("", resource),
		PerformanceInsights:       adaptPerformanceInsights(resource),
		Instances:                 clusterInstances,
		Encryption:                adaptEncryption(resource),
	}, ids
}

func getClusterInstances(resource block.Block, modules block.Modules) (clusterInstances []rds.ClusterInstance, instanceIDs []string) {
	clusterInstanceResources := modules.GetReferencingResources(resource, "aws_rds_cluster_instance", "cluster_identifier")

	for _, ciResource := range clusterInstanceResources {
		instanceIDs = append(instanceIDs, ciResource.ID())
		clusterInstances = append(clusterInstances, adaptClusterInstance(ciResource, modules))
	}
	return clusterInstances, instanceIDs
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
