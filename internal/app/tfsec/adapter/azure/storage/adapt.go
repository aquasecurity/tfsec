package storage

import (
	"github.com/aquasecurity/defsec/provider/azure/storage"
	"github.com/aquasecurity/defsec/types"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func Adapt(modules []block.Module) storage.Storage {
	return storage.Storage{
		Accounts: adaptAccounts(modules),
	}
}

func adaptAccounts(modules []block.Module) []storage.Account {
	var accounts []storage.Account

	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("azurerm_storage_account") {
			account := adaptAccount(resource)
			containerResource := module.GetReferencingResources(resource, "azurerm_storage_container", "storage_account_name")
			for _, containerBlock := range containerResource {
				account.Containers = append(account.Containers, adaptContainer(containerBlock))
			}
			networkRulesResource := module.GetReferencingResources(resource, "azurerm_storage_account_network_rules", "storage_account_name")
			for _, networkRuleBlock := range networkRulesResource {
				account.NetworkRules = append(account.NetworkRules, adaptNetworkRule(networkRuleBlock))
			}
			accounts = append(accounts, account)
		}
	}

	return accounts
}

func adaptAccount(resource block.Block) storage.Account {
	var networkRules []storage.NetworkRule
	networkRulesBlocks := resource.GetBlocks("network_rules")
	for _, networkBlock := range networkRulesBlocks {
		networkRules = append(networkRules, adaptNetworkRule(networkBlock))
	}

	httpsOnlyAttr := resource.GetAttribute("enable_https_traffic_only")
	httpsOnlyVal := httpsOnlyAttr.AsBoolValueOrDefault(true, resource)

	enableLogging := types.Bool(false, *resource.GetMetadata())
	queuePropertiesBlock := resource.GetBlock("queue_properties")
	if queuePropertiesBlock.IsNotNil() {
		loggingBlock := queuePropertiesBlock.GetBlock("logging")
		if loggingBlock.IsNotNil() {
			enableLogging = types.Bool(true, *loggingBlock.GetMetadata())
		}
	}

	minTLSVersionAttr := resource.GetAttribute("min_tls_version")
	minTLSVersionVal := minTLSVersionAttr.AsStringValueOrDefault("TLS1_0", resource)

	return storage.Account{
		NetworkRules: networkRules,
		EnforceHTTPS: httpsOnlyVal,
		QueueProperties: storage.QueueProperties{
			EnableLogging: enableLogging,
		},
		MinimumTLSVersion: minTLSVersionVal,
	}
}

func adaptContainer(resource block.Block) storage.Container {
	accessTypeAttr := resource.GetAttribute("container_access_type")
	publicAccess := types.String(storage.PublicAccessOff, *resource.GetMetadata())

	if accessTypeAttr.Equals("blob") {
		publicAccess = types.String(storage.PublicAccessBlob, *resource.GetMetadata())
	} else if accessTypeAttr.Equals("container") {
		publicAccess = types.String(storage.PublicAccessContainer, *resource.GetMetadata())
	}

	return storage.Container{
		PublicAccess: publicAccess,
	}
}

func adaptNetworkRule(resource block.Block) storage.NetworkRule {
	var allowByDefault types.BoolValue
	var bypass []types.StringValue

	defaultActionAttr := resource.GetAttribute("default_action")
	if defaultActionAttr.Equals("allow", block.IgnoreCase) {
		allowByDefault = types.Bool(true, *resource.GetMetadata())
	} else if defaultActionAttr.Equals("deny", block.IgnoreCase) {
		allowByDefault = types.Bool(false, *resource.GetMetadata())
	}

	if resource.HasChild("bypass") {
		bypassAttr := resource.GetAttribute("bypass")
		bypassList := bypassAttr.ValueAsStrings()
		for _, bypassVal := range bypassList {
			bypass = append(bypass, types.String(bypassVal, *resource.GetMetadata()))
		}
	}

	return storage.NetworkRule{
		Metadata:       *resource.GetMetadata(),
		Bypass:         bypass,
		AllowByDefault: allowByDefault,
	}
}
