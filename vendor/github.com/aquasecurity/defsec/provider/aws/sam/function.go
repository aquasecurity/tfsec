package sam

import (
	"github.com/aquasecurity/defsec/provider/aws/iam"
	"github.com/aquasecurity/defsec/types"
)

type Function struct {
	types.Metadata
	FunctionName    types.StringValue
	Tracing         types.StringValue
	ManagedPolicies []types.StringValue
	Policies        []iam.PolicyDocument
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

func (c *Function) GetMetadata() *types.Metadata {
	return &c.Metadata
}

func (c *Function) GetRawValue() interface{} {
	return nil
}


func (c *Permission) GetMetadata() *types.Metadata {
	return &c.Metadata
}

func (c *Permission) GetRawValue() interface{} {
	return nil
}
