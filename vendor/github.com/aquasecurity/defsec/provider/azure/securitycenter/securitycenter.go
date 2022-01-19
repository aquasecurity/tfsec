package securitycenter

import "github.com/aquasecurity/defsec/types"

type SecurityCenter struct {
	types.Metadata
	Contacts      []Contact
	Subscriptions []SubscriptionPricing
}

type Contact struct {
	types.Metadata
	EnableAlertNotifications types.BoolValue
	Phone                    types.StringValue
}

const (
	TierFree     = "Free"
	TierStandard = "Standard"
)

type SubscriptionPricing struct {
	types.Metadata
	Tier types.StringValue
}


func (s *SecurityCenter) GetMetadata() *types.Metadata {
	return &s.Metadata
}

func (s *SecurityCenter) GetRawValue() interface{} {
	return nil
}    


func (c *Contact) GetMetadata() *types.Metadata {
	return &c.Metadata
}

func (c *Contact) GetRawValue() interface{} {
	return nil
}    


func (s *SubscriptionPricing) GetMetadata() *types.Metadata {
	return &s.Metadata
}

func (s *SubscriptionPricing) GetRawValue() interface{} {
	return nil
}    
