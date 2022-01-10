package redshift

import (
	"github.com/aquasecurity/defsec/provider/aws/redshift"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func Adapt(modules []block.Module) redshift.Redshift {
	return redshift.Redshift{
		Clusters:       adaptClusters(modules),
		SecurityGroups: adaptSecurityGroups(modules),
	}
}

func adaptClusters(modules []block.Module) []redshift.Cluster {
	var clusters []redshift.Cluster
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_redshift_cluster") {
			clusters = append(clusters, adaptCluster(resource))
		}
	}
	return clusters
}

func adaptSecurityGroups(modules []block.Module) []redshift.SecurityGroup {
	var securityGroups []redshift.SecurityGroup
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_redshift_security_group") {
			securityGroups = append(securityGroups, adaptSecurityGroup(resource))
		}
	}
	return securityGroups
}

func adaptCluster(resource block.Block) redshift.Cluster {
	encryptedAttr := resource.GetAttribute("encrypted")
	encryptedVal := encryptedAttr.AsBoolValueOrDefault(false, resource)

	KMSKeyIDAttr := resource.GetAttribute("kms_key_id")
	KMSKeyIDVal := KMSKeyIDAttr.AsStringValueOrDefault("", resource)

	subnetGroupNameAttr := resource.GetAttribute("cluster_subnet_group_name")
	subnetGroupNameVal := subnetGroupNameAttr.AsStringValueOrDefault("", resource)

	return redshift.Cluster{
		Metadata: *resource.GetMetadata(),
		Encryption: redshift.Encryption{
			Enabled:  encryptedVal,
			KMSKeyID: KMSKeyIDVal,
		},
		SubnetGroupName: subnetGroupNameVal,
	}
}

func adaptSecurityGroup(resource block.Block) redshift.SecurityGroup {
	descriptionAttr := resource.GetAttribute("description")
	descriptionVal := descriptionAttr.AsStringValueOrDefault("Managed by Terraform", resource)

	return redshift.SecurityGroup{
		Metadata:    *resource.GetMetadata(),
		Description: descriptionVal,
	}
}
