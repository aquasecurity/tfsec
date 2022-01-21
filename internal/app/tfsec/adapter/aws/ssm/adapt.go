package ssm

import (
	"github.com/aquasecurity/defsec/provider/aws/ssm"
	"github.com/aquasecurity/defsec/types"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func Adapt(modules block.Modules) ssm.SSM {
	return ssm.SSM{
		Secrets: adaptSecrets(modules),
	}
}

func adaptSecrets(modules block.Modules) []ssm.Secret {
	var secrets []ssm.Secret
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_secretsmanager_secret") {
			secrets = append(secrets, adaptSecret(resource, module))
		}
	}
	return secrets
}

func adaptSecret(resource *block.Block, module *block.Module) ssm.Secret {
	KMSKeyIDAttr := resource.GetAttribute("kms_key_id")
	KMSKeyIDVal := KMSKeyIDAttr.AsStringValueOrDefault("alias/aws/secretsmanager", resource)

	if KMSKeyIDAttr.IsDataBlockReference() {
		kmsData, err := module.GetReferencedBlock(KMSKeyIDAttr, resource)
		if err != nil {
			KMSKeyIDVal = types.StringDefault("alias/aws/secretsmanager", KMSKeyIDAttr.Metadata())
		} else {
			keyIDAttr := kmsData.GetAttribute("key_id")
			KMSKeyIDVal = keyIDAttr.AsStringValueOrDefault("alias/aws/secretsmanager", kmsData)
		}
	}

	return ssm.Secret{
		Metadata: *resource.GetMetadata(),
		KMSKeyID: KMSKeyIDVal,
	}
}
