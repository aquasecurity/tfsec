package redshift

import (
	"github.com/aquasecurity/defsec/provider/aws/redshift"
	"github.com/aquasecurity/defsec/types"
	"github.com/aquasecurity/tfsec/internal/pkg/block"
)

func Adapt(modules block.Modules) redshift.Redshift {
	return redshift.Redshift{
		Clusters:       adaptClusters(modules),
		SecurityGroups: adaptSecurityGroups(modules),
	}
}

func adaptClusters(modules block.Modules) []redshift.Cluster {
	var clusters []redshift.Cluster
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_redshift_cluster") {
			clusters = append(clusters, adaptCluster(resource))
		}
	}
	return clusters
}

func adaptSecurityGroups(modules block.Modules) []redshift.SecurityGroup {
	var securityGroups []redshift.SecurityGroup
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_redshift_security_group") {
			securityGroups = append(securityGroups, adaptSecurityGroup(resource))
		}
	}
	return securityGroups
}

func adaptCluster(resource *block.Block) redshift.Cluster {
	cluster := redshift.Cluster{
		Metadata: resource.Metadata(),
		Encryption: redshift.Encryption{
			Metadata: resource.Metadata(),
			Enabled:  types.BoolDefault(false, resource.Metadata()),
			KMSKeyID: types.StringDefault("", resource.Metadata()),
		},
		SubnetGroupName: types.StringDefault("", resource.Metadata()),
	}

	encryptedAttr := resource.GetAttribute("encrypted")
	cluster.Encryption.Enabled = encryptedAttr.AsBoolValueOrDefault(false, resource)

	KMSKeyIDAttr := resource.GetAttribute("kms_key_id")
	cluster.Encryption.KMSKeyID = KMSKeyIDAttr.AsStringValueOrDefault("", resource)

	subnetGroupNameAttr := resource.GetAttribute("cluster_subnet_group_name")
	cluster.SubnetGroupName = subnetGroupNameAttr.AsStringValueOrDefault("", resource)

	return cluster
}

func adaptSecurityGroup(resource *block.Block) redshift.SecurityGroup {
	descriptionAttr := resource.GetAttribute("description")
	descriptionVal := descriptionAttr.AsStringValueOrDefault("Managed by Terraform", resource)

	return redshift.SecurityGroup{
		Metadata:    resource.Metadata(),
		Description: descriptionVal,
	}
}
