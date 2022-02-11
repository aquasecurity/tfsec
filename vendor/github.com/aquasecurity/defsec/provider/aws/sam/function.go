package sam

import (
	"github.com/aquasecurity/trivy-config-parsers/types"
)

type Function struct {
	types.Metadata
	FunctionName    types.StringValue
	Tracing         types.StringValue
	ManagedPolicies []types.StringValue
	Policies        []types.StringValue
}

const (
	TracingModePassThrough = "PassThrough"
	TracingModeActive      = "Active"
)

type Permission struct {
	types.Metadata
	Principal types.StringValue
	SourceARN types.StringValue
}
