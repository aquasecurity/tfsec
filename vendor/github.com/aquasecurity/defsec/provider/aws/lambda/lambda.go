package lambda

import "github.com/aquasecurity/defsec/types"

type Lambda struct {
	Functions []Function
}

type Function struct {
	types.Metadata
	Tracing     Tracing
	Permissions []Permission
}

const (
	TracingModePassThrough = "PassThrough"
	TracingModeActive      = "Active"
)

type Tracing struct {
	Mode types.StringValue
}

type Permission struct {
	Principal types.StringValue
	SourceARN types.StringValue
}

func (c *Function) GetMetadata() *types.Metadata {
	return &c.Metadata
}

func (c *Function) GetRawValue() interface{} {
	return nil
}
