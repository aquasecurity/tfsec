package keyvault

import (
	"time"

	"github.com/aquasecurity/defsec/provider/azure/keyvault"
	"github.com/aquasecurity/defsec/types"
	"github.com/aquasecurity/tfsec/internal/pkg/block"
)

func Adapt(modules block.Modules) keyvault.KeyVault {
	adapter := adapter{
		vaultSecretIDs: modules.GetChildResourceIDMapByType("azurerm_key_vault_secret"),
		vaultKeyIDs:    modules.GetChildResourceIDMapByType("azurerm_key_vault_key"),
	}

	return keyvault.KeyVault{
		Vaults: adapter.adaptVaults(modules),
	}
}

type adapter struct {
	vaultSecretIDs block.ResourceIDResolutions
	vaultKeyIDs    block.ResourceIDResolutions
}

func (a *adapter) adaptVaults(modules block.Modules) []keyvault.Vault {

	var vaults []keyvault.Vault
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("azurerm_key_vault") {
			vaults = append(vaults, a.adaptVault(resource, module))

		}
	}

	orphanResources := modules.GetResourceByIDs(a.vaultSecretIDs.Orphans()...)

	if len(orphanResources) > 0 {
		orphanage := keyvault.Vault{
			Metadata: types.NewUnmanagedMetadata(),
		}
		for _, secretResource := range orphanResources {
			orphanage.Secrets = append(orphanage.Secrets, adaptSecret(secretResource))
		}
		vaults = append(vaults, orphanage)
	}

	orphanResources = modules.GetResourceByIDs(a.vaultKeyIDs.Orphans()...)

	if len(orphanResources) > 0 {
		orphanage := keyvault.Vault{
			Metadata: types.NewUnmanagedMetadata(),
		}
		for _, secretResource := range orphanResources {
			orphanage.Keys = append(orphanage.Keys, adaptKey(secretResource))
		}
		vaults = append(vaults, orphanage)
	}

	return vaults
}

func (a *adapter) adaptVault(resource *block.Block, module *block.Module) keyvault.Vault {
	var keys []keyvault.Key
	var secrets []keyvault.Secret

	defaultActionVal := types.StringDefault("", *resource.GetMetadata())

	secretBlocks := module.GetReferencingResources(resource, "azurerm_key_vault_secret", "key_vault_id")
	for _, secretBlock := range secretBlocks {
		a.vaultSecretIDs.Resolve(secretBlock.ID())
		secrets = append(secrets, adaptSecret(secretBlock))
	}

	keyBlocks := module.GetReferencingResources(resource, "azurerm_key_vault_key", "key_vault_id")
	for _, keyBlock := range keyBlocks {
		a.vaultKeyIDs.Resolve(keyBlock.ID())
		keys = append(keys, adaptKey(keyBlock))
	}

	purgeProtectionAttr := resource.GetAttribute("purge_protection_enabled")
	purgeProtectionVal := purgeProtectionAttr.AsBoolValueOrDefault(false, resource)

	softDeleteRetentionDaysAttr := resource.GetAttribute("soft_delete_retention_days")
	softDeleteRetentionDaysVal := softDeleteRetentionDaysAttr.AsIntValueOrDefault(0, resource)

	aclMetadata := types.NewUnmanagedMetadata()
	if aclBlock := resource.GetBlock("network_acls"); aclBlock.IsNotNil() {
		aclMetadata = aclBlock.Metadata()
		defaultActionAttr := aclBlock.GetAttribute("default_action")
		defaultActionVal = defaultActionAttr.AsStringValueOrDefault("", resource.GetBlock("network_acls"))
	}

	return keyvault.Vault{
		Metadata:                resource.Metadata(),
		Secrets:                 secrets,
		Keys:                    keys,
		EnablePurgeProtection:   purgeProtectionVal,
		SoftDeleteRetentionDays: softDeleteRetentionDaysVal,
		NetworkACLs: keyvault.NetworkACLs{
			Metadata:      aclMetadata,
			DefaultAction: defaultActionVal,
		},
	}
}

func adaptSecret(resource *block.Block) keyvault.Secret {
	contentTypeAttr := resource.GetAttribute("content_type")
	contentTypeVal := contentTypeAttr.AsStringValueOrDefault("", resource)

	expiryDateAttr := resource.GetAttribute("expiration_date")
	expiryDateVal := types.TimeDefault(time.Time{}, resource.GetMetadata())

	if expiryDateAttr.IsString() {
		expiryDateString := expiryDateAttr.Value().AsString()
		layout := "2006-01-02T15:04:00Z"
		if expiryDate, err := time.Parse(layout, expiryDateString); err == nil {
			expiryDateVal = types.Time(expiryDate, expiryDateAttr.GetMetadata())
		}
	}

	return keyvault.Secret{
		Metadata:    resource.Metadata(),
		ContentType: contentTypeVal,
		ExpiryDate:  expiryDateVal,
	}
}

func adaptKey(resource *block.Block) keyvault.Key {
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
		Metadata:   resource.Metadata(),
		ExpiryDate: expiryDateVal,
	}
}
