package securitycenter

import "github.com/aquasecurity/defsec/types"

type SecurityCenter struct {
	Contacts      []Contact
	Subscriptions []SubscriptionPricing
}

type Contact struct {
	EnableAlertNotifications types.BoolValue
	Phone                    types.StringValue
}

const (
	TierFree     = "Free"
	TierStandard = "Standard"
)

type SubscriptionPricing struct {
	Tier types.StringValue
}
