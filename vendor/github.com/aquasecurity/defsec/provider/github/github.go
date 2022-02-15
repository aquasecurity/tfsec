package github

import "github.com/aquasecurity/trivy-config-parsers/types"

type GitHub struct {
	types.Metadata
	Repositories       []Repository
	EnvironmentSecrets []EnvironmentSecret
}
