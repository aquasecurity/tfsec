package secrets

import (
	"github.com/aquasecurity/defsec/provider/github"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func Adapt(modules block.Modules) []github.EnvironmentSecret {
	return adaptSecrets(modules)
}

func adaptSecrets(modules block.Modules) []github.EnvironmentSecret {
	var secrets []github.EnvironmentSecret
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("github_actions_environment_secret") {
			secrets = append(secrets, adaptSecret(resource))
		}
	}
	return secrets
}

func adaptSecret(resource block.Block) github.EnvironmentSecret {
	var secret github.EnvironmentSecret
	secret.SecretName = resource.GetAttribute("secret_name").AsStringValueOrDefault("", resource)
	secret.PlainTextValue = resource.GetAttribute("plaintext_value").AsStringValueOrDefault("", resource)
	secret.Environment = resource.GetAttribute("environment").AsStringValueOrDefault("", resource)
	secret.Repository = resource.GetAttribute("repository").AsStringValueOrDefault("", resource)
	secret.EncryptedValue = resource.GetAttribute("encrypted_value").AsStringValueOrDefault("", resource)
	return secret
}
