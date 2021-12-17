package types

import "strings"

type StringEqualityOption int

const (
	IgnoreCase StringEqualityOption = iota
)

func String(str string, m Metadata) StringValue {
	return &stringValue{
		value:    str,
		metadata: m,
	}
}
func StringDefault(value string, m Metadata) StringValue {
	b := String(value, m)
	b.GetMetadata().isDefault = true
	return b
}
func StringUnresolvable(m Metadata) StringValue {
	b := String("", m)
	b.GetMetadata().isUnresolvable = true
	return b
}

func StringExplicit(value string, m Metadata) StringValue {
	b := String(value, m)
	b.GetMetadata().isExplicit = true
	return b
}

type StringValue interface {
	metadataProvider
	Value() string
	IsEmpty() bool
	IsNotEmpty() bool
	IsOneOf(values ...string) bool
	EqualTo(value string, equalityOptions ...StringEqualityOption) bool
	NotEqualTo(value string, equalityOptions ...StringEqualityOption) bool
	StartsWith(prefix string, equalityOptions ...StringEqualityOption) bool
	EndsWith(suffix string, equalityOptions ...StringEqualityOption) bool
	Contains(value string, equalityOptions ...StringEqualityOption) bool
}

type stringValue struct {
	metadata Metadata
	value    string
}

type stringCheckFunc func(string, string) bool

func (s *stringValue) IsOneOf(values ...string) bool {
	if s.metadata.isUnresolvable {
		return false
	}
	for _, value := range values {
		if value == s.value {
			return true
		}
	}
	return false
}

func (s *stringValue) GetMetadata() *Metadata {
	return &s.metadata
}

func (s *stringValue) Value() string {
	return s.value
}

func (b *stringValue) GetRawValue() interface{} {
	return b.value
}

func (s *stringValue) IsEmpty() bool {
	if s.metadata.isUnresolvable {
		return false
	}
	return s.value == ""
}

func (s *stringValue) IsNotEmpty() bool {
	if s.metadata.isUnresolvable {
		return false
	}
	return s.value != ""
}

func (s *stringValue) EqualTo(value string, equalityOptions ...StringEqualityOption) bool {
	if s.metadata.isUnresolvable {
		return false
	}

	return s.executePredicate(value, func(a, b string) bool { return a == b }, equalityOptions...)
}

func (s *stringValue) NotEqualTo(value string, equalityOptions ...StringEqualityOption) bool {
	if s.metadata.isUnresolvable {
		return false
	}

	return !s.EqualTo(value, equalityOptions...)
}

func (s *stringValue) StartsWith(prefix string, equalityOptions ...StringEqualityOption) bool {
	if s.metadata.isUnresolvable {
		return false
	}

	return s.executePredicate(prefix, strings.HasPrefix, equalityOptions...)
}

func (s *stringValue) EndsWith(suffix string, equalityOptions ...StringEqualityOption) bool {
	if s.metadata.isUnresolvable {
		return false
	}
	return s.executePredicate(suffix, strings.HasSuffix, equalityOptions...)
}

func (s *stringValue) Contains(value string, equalityOptions ...StringEqualityOption) bool {
	if s.metadata.isUnresolvable {
		return false
	}
	return s.executePredicate(value, strings.Contains, equalityOptions...)
}

func (s *stringValue) executePredicate(value string, fn stringCheckFunc, equalityOptions ...StringEqualityOption) bool {
	subjectString := s.value
	searchString := value

	for _, eqOpt := range equalityOptions {
		switch eqOpt {
		case IgnoreCase:
			subjectString = strings.ToLower(subjectString)
			searchString = strings.ToLower(searchString)
		}
	}

	return fn(subjectString, searchString)
}
