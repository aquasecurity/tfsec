package github

import "github.com/aquasecurity/defsec/types"

type GitHub struct {
	types.Metadata
	Repositories       []Repository
	EnvironmentSecrets []EnvironmentSecret
}
