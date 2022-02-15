package compute

import "github.com/aquasecurity/trivy-config-parsers/types"

type SubNetwork struct {
	types.Metadata
	Name           types.StringValue
	EnableFlowLogs types.BoolValue
}
