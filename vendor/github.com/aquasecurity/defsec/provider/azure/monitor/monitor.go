package monitor

import "github.com/aquasecurity/defsec/types"

type Monitor struct {
	types.Metadata
	LogProfiles []LogProfile
}

type LogProfile struct {
	types.Metadata
	RetentionPolicy RetentionPolicy
	Categories      []types.StringValue
	Locations       []types.StringValue
}

type RetentionPolicy struct {
	types.Metadata
	Enabled types.BoolValue
	Days    types.IntValue
}

func (m *Monitor) GetMetadata() *types.Metadata {
	return &m.Metadata
}

func (m *Monitor) GetRawValue() interface{} {
	return nil
}

func (l *LogProfile) GetMetadata() *types.Metadata {
	return &l.Metadata
}

func (l *LogProfile) GetRawValue() interface{} {
	return nil
}

func (r *RetentionPolicy) GetMetadata() *types.Metadata {
	return &r.Metadata
}

func (r *RetentionPolicy) GetRawValue() interface{} {
	return nil
}
