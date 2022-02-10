package compute

import "github.com/aquasecurity/trivy-config-parsers/types"

type ProjectMetadata struct {
	types.Metadata
	EnableOSLogin types.BoolValue
}
