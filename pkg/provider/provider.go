package provider

import "strings"

// Provider is the provider that the check applies to
type Provider string

const (
	UnknownProvider      Provider = ""
	AWSProvider          Provider = "aws"
	AzureProvider        Provider = "azure"
	CustomProvider       Provider = "custom"
	DigitalOceanProvider Provider = "digitalocean"
	GeneralProvider      Provider = "general"
	GitHubProvider       Provider = "github"
	GoogleProvider       Provider = "google"
	OracleProvider       Provider = "oracle"
	OpenStackProvider    Provider = "openstack"
)

func RuleProviderToString(provider Provider) string {
	return strings.ToUpper(string(provider))
}
