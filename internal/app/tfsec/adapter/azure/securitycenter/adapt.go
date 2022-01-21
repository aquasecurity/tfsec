package securitycenter

import (
	"github.com/aquasecurity/defsec/provider/azure/securitycenter"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func Adapt(modules block.Modules) securitycenter.SecurityCenter {
	return securitycenter.SecurityCenter{
		Contacts:      adaptContacts(modules),
		Subscriptions: adaptSubscriptions(modules),
	}
}

func adaptContacts(modules block.Modules) []securitycenter.Contact {
	var contacts []securitycenter.Contact

	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("azurerm_security_center_contact") {
			contacts = append(contacts, adaptContact(resource))
		}
	}
	return contacts
}

func adaptSubscriptions(modules block.Modules) []securitycenter.SubscriptionPricing {
	var subscriptions []securitycenter.SubscriptionPricing

	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("azurerm_security_center_subscription_pricing") {
			subscriptions = append(subscriptions, adaptSubscription(resource))
		}
	}
	return subscriptions
}

func adaptContact(resource *block.Block) securitycenter.Contact {
	enableAlertNotifAttr := resource.GetAttribute("alert_notifications")
	enableAlertNotifVal := enableAlertNotifAttr.AsBoolValueOrDefault(false, resource)

	phoneAttr := resource.GetAttribute("phone")
	phoneVal := phoneAttr.AsStringValueOrDefault("", resource)

	return securitycenter.Contact{
		EnableAlertNotifications: enableAlertNotifVal,
		Phone:                    phoneVal,
	}
}

func adaptSubscription(resource *block.Block) securitycenter.SubscriptionPricing {
	tierAttr := resource.GetAttribute("tier")
	tierVal := tierAttr.AsStringValueOrDefault("", resource)

	return securitycenter.SubscriptionPricing{
		Tier: tierVal,
	}
}
