package types

import "time"

type TimeValue interface {
	metadataProvider
	Value() *time.Time
	LessThan(i time.Time) bool
	GreaterThan(i time.Time) bool
	IsNever() bool
}

type timeValue struct {
	metadata *Metadata
	value    *time.Time
}

func Time(value time.Time, m *Metadata) TimeValue {
	return &timeValue{
		value:    &value,
		metadata: m,
	}
}

func TimeDefault(value time.Time, m *Metadata) TimeValue {
	b := Time(value, m)
	b.GetMetadata().isDefault = true
	return b
}

func TimeExplicit(value time.Time, m *Metadata) TimeValue {
	b := Time(value, m)
	b.GetMetadata().isExplicit = true
	return b
}

func (b *timeValue) GetMetadata() *Metadata {
	return b.metadata
}

func (b *timeValue) Value() *time.Time {
	return b.value
}

func (b *timeValue) GetRawValue() interface{} {
	return b.value
}

func (b *timeValue) IsNever() bool {
	return b.value == nil
}

func (b *timeValue) LessThan(i time.Time) bool {
	if b.metadata.isUnresolvable {
		return false
	}
	if b.value == nil {
		return false
	}
	return b.value.Before(i)
}

func (b *timeValue) GreaterThan(i time.Time) bool {
	if b.metadata.isUnresolvable {
		return false
	}
	if b.value == nil {
		return false
	}
	return b.value.After(i)
}
