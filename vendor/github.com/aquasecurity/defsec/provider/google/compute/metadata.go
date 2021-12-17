package compute

import "github.com/aquasecurity/defsec/types"

type ProjectMetadata struct {
	types.Metadata
	EnableOSLogin types.BoolValue
}
