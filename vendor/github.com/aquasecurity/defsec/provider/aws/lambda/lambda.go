package lambda

import "github.com/aquasecurity/defsec/types"

type Lambda struct {
	types.Metadata
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
	types.Metadata
	Mode types.StringValue
}

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


func (l *Lambda) GetMetadata() *types.Metadata {
	return &l.Metadata
}

func (l *Lambda) GetRawValue() interface{} {
	return nil
}    


func (t *Tracing) GetMetadata() *types.Metadata {
	return &t.Metadata
}

func (t *Tracing) GetRawValue() interface{} {
	return nil
}    


func (p *Permission) GetMetadata() *types.Metadata {
	return &p.Metadata
}

func (p *Permission) GetRawValue() interface{} {
	return nil
}    
