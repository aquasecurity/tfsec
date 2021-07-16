package provider

import "strings"

// Provider is the provider that the check applies to
type Provider string

const (
	UnknownProvider      Provider = ""
	AWSProvider          Provider = "aws"
	AzureProvider        Provider = "azure"
	GCPProvider          Provider = "google"
	GeneralProvider      Provider = "general"
	OracleProvider       Provider = "oracle"
	DigitalOceanProvider Provider = "digitalocean"
	CustomProvider       Provider = "custom"
	GitHubProvider       Provider = "github"
)

func RuleProviderToString(provider Provider) string {
	return strings.ToUpper(string(provider))
}
