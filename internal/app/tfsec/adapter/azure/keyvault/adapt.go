package keyvault

import (
	"time"

	"github.com/aquasecurity/defsec/provider/azure/keyvault"
	"github.com/aquasecurity/defsec/types"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func Adapt(modules []block.Module) keyvault.KeyVault {
	return keyvault.KeyVault{
		Vaults: adaptVaults(modules),
	}
}

func adaptVaults(modules []block.Module) []keyvault.Vault {
	var vaults []keyvault.Vault
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("azurerm_key_vault") {
			vaults = append(vaults, adaptVault(resource, module))

		}
	}
	return vaults
}

func adaptVault(resource block.Block, module block.Module) keyvault.Vault {
	var keys []keyvault.Key
	var secrets []keyvault.Secret

	defaultActionVal := types.StringDefault("", *resource.GetMetadata())

	secretBlocks := module.GetReferencingResources(resource, "azurerm_key_vault_secret", "key_vault_id")
	for _, secretBlock := range secretBlocks {
		secrets = append(secrets, adaptSecret(secretBlock))
	}

	keyBlocks := module.GetReferencingResources(resource, "azurerm_key_vault_key", "key_vault_id")
	for _, keyBlock := range keyBlocks {
		keys = append(keys, adaptKey(keyBlock))
	}

	purgeProtectionAttr := resource.GetAttribute("purge_protection_enabled")
	purgeProtectionVal := purgeProtectionAttr.AsBoolValueOrDefault(false, resource)

	softDeleteRetentionDaysAttr := resource.GetAttribute("soft_delete_retention_days")
	softDeleteRetentionDaysVal := softDeleteRetentionDaysAttr.AsIntValueOrDefault(0, resource)

	if resource.HasChild("network_acls") {
		defaultActionAttr := resource.GetBlock("network_acls").GetAttribute("default_action")
		defaultActionVal = defaultActionAttr.AsStringValueOrDefault("", resource.GetBlock("network_acls"))
	}

	return keyvault.Vault{
		Secrets:                 secrets,
		Keys:                    keys,
		EnablePurgeProtection:   purgeProtectionVal,
		SoftDeleteRetentionDays: softDeleteRetentionDaysVal,
		NetworkACLs: keyvault.NetworkACLs{
			DefaultAction: defaultActionVal,
		},
	}
}

func adaptSecret(resource block.Block) keyvault.Secret {
	contentTypeAttr := resource.GetAttribute("content_type")
	contentTypeVal := contentTypeAttr.AsStringValueOrDefault("", resource)

	expiryDateAttr := resource.GetAttribute("expiration_date")
	expiryDateVal := types.TimeDefault(time.Time{}, resource.GetMetadata())

	if expiryDateAttr.IsNotNil() {
		expiryDateString := expiryDateAttr.Value().AsString()
		layout := "2006-01-02T15:04:00Z"
		if expiryDate, err := time.Parse(layout, expiryDateString); err == nil {
			expiryDateVal = types.Time(expiryDate, expiryDateAttr.GetMetadata())
		}
	}

	return keyvault.Secret{
		ContentType: contentTypeVal,
		ExpiryDate:  expiryDateVal,
	}
}

func adaptKey(resource block.Block) keyvault.Key {
	expiryDateAttr := resource.GetAttribute("expiration_date")
	expiryDateVal := types.TimeDefault(time.Time{}, resource.GetMetadata())

	if expiryDateAttr.IsNotNil() {
		expiryDateString := expiryDateAttr.Value().AsString()
		layout := "2006-01-02T15:04:00Z"
		if expiryDate, err := time.Parse(layout, expiryDateString); err == nil {
			expiryDateVal = types.Time(expiryDate, expiryDateAttr.GetMetadata())
		}
	}

	return keyvault.Key{
		ExpiryDate: expiryDateVal,
	}
}
