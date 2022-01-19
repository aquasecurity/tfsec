package github

import "github.com/aquasecurity/defsec/types"

type Repository struct {
	types.Metadata
	Public types.BoolValue
}
