package github

import "github.com/aquasecurity/trivy-config-parsers/types"

type Repository struct {
	types.Metadata
	Public types.BoolValue
}
