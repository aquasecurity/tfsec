package sam

import (
	"github.com/aquasecurity/defsec/provider/aws/iam"
	"github.com/aquasecurity/defsec/types"
)

type StateMachine struct {
	types.Metadata
	Name                 types.StringValue
	LoggingConfiguration LoggingConfiguration
	ManagedPolicies      []types.StringValue
	Policies             []iam.PolicyDocument
	Tracing              TracingConfiguration
}

type LoggingConfiguration struct {
	types.Metadata
	LoggingEnabled types.BoolValue
}

type TracingConfiguration struct {
	types.Metadata
	Enabled types.BoolValue
}

func (a *StateMachine) GetMetadata() *types.Metadata {
	return &a.Metadata
}

func (a *StateMachine) GetRawValue() interface{} {
	return nil
}

func (a *LoggingConfiguration) GetMetadata() *types.Metadata {
	return &a.Metadata
}

func (a *LoggingConfiguration) GetRawValue() interface{} {
	return nil
}

func (a *TracingConfiguration) GetMetadata() *types.Metadata {
	return &a.Metadata
}

func (a *TracingConfiguration) GetRawValue() interface{} {
	return nil
}
