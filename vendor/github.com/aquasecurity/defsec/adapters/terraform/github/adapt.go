package github

import (
	"github.com/aquasecurity/defsec/adapters/terraform/github/repositories"
	"github.com/aquasecurity/defsec/adapters/terraform/github/secrets"
	"github.com/aquasecurity/defsec/provider/github"
	"github.com/aquasecurity/trivy-config-parsers/terraform"
)

func Adapt(modules terraform.Modules) github.GitHub {
	return github.GitHub{
		Repositories:       repositories.Adapt(modules),
		EnvironmentSecrets: secrets.Adapt(modules),
	}
}
