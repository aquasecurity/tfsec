package athena

import (
	"github.com/aquasecurity/defsec/types"

	"github.com/aquasecurity/defsec/provider/aws/athena"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func Adapt(modules []block.Module) athena.Athena {
	return athena.Athena{
		Databases:  adaptDatabases(modules),
		Workgroups: adaptWorkgroups(modules),
	}
}

func adaptDatabases(modules []block.Module) []athena.Database {
	var databases []athena.Database
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_athena_database") {
			databases = append(databases, adaptDatabase(resource))
		}
	}
	return databases
}

func adaptWorkgroups(modules []block.Module) []athena.Workgroup {
	var workgroups []athena.Workgroup
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_athena_workgroup") {
			workgroups = append(workgroups, adaptWorkgroup(resource))
		}
	}
	return workgroups
}

func adaptDatabase(resource block.Block) athena.Database {
	nameAttr := resource.GetAttribute("name")
	nameVal := nameAttr.AsStringValueOrDefault("", resource)

	encryptionOptionVal := types.StringDefault("", *resource.GetMetadata())

	if resource.HasChild("encryption_configuration") {
		encryptionConfigBlock := resource.GetBlock("encryption_configuration")
		encryptionOptionAttr := encryptionConfigBlock.GetAttribute("encryption_option")
		encryptionOptionVal = encryptionOptionAttr.AsStringValueOrDefault("", encryptionConfigBlock)
	}

	return athena.Database{
		Metadata: *resource.GetMetadata(),
		Name:     nameVal,
		Encryption: athena.EncryptionConfiguration{
			Type: encryptionOptionVal,
		},
	}
}

func adaptWorkgroup(resource block.Block) athena.Workgroup {
	nameAttr := resource.GetAttribute("name")
	nameVal := nameAttr.AsStringValueOrDefault("", resource)

	enforceWGConfigVal := types.BoolDefault(false, *resource.GetMetadata())
	encryptionOptionVal := types.StringDefault("", *resource.GetMetadata())

	if resource.HasChild("configuration") {
		configBlock := resource.GetBlock("configuration")

		enforceWGConfigAttr := configBlock.GetAttribute("enforce_workgroup_configuration")
		enforceWGConfigVal = enforceWGConfigAttr.AsBoolValueOrDefault(true, configBlock)

		if configBlock.HasChild("result_configuration") {
			resultConfigBlock := configBlock.GetBlock("result_configuration")
			if resultConfigBlock.HasChild("encryption_configuration") {
				encryptionConfigBlock := resultConfigBlock.GetBlock("encryption_configuration")
				encryptionOptionAttr := encryptionConfigBlock.GetAttribute("encryption_option")
				encryptionOptionVal = encryptionOptionAttr.AsStringValueOrDefault("", encryptionConfigBlock)
			}
		}
	}

	return athena.Workgroup{
		Metadata: *resource.GetMetadata(),
		Name:     nameVal,
		Encryption: athena.EncryptionConfiguration{
			Type: encryptionOptionVal,
		},
		EnforceConfiguration: enforceWGConfigVal,
	}
}
