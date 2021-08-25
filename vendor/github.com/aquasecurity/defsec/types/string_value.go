package types

import "strings"

type StringEqualityOption int

const (
	IgnoreCase StringEqualityOption = iota
)

func String(str string, r Range, ref Reference) StringValue {
	return &stringValue{
		value:    str,
		metadata: NewMetadata(r, ref),
	}
}
func StringDefault(value string, r Range, ref Reference) StringValue {
	b := String(value, r, ref)
	b.Metadata().isDefault = true
	return b
}

func StringExplicit(value string, r Range, ref Reference) StringValue {
	b := String(value, r, ref)
	b.Metadata().isExplicit = true
	return b
}

type StringValue interface {
	metadataProvider
	Value() string
	IsEmpty() bool
	EqualTo(value string, equalityOptions ...StringEqualityOption) bool
	NotEqualTo(value string, equalityOptions ...StringEqualityOption) bool
	StartsWith(prefix string, equalityOptions ...StringEqualityOption) bool
	EndsWith(suffix string, equalityOptions ...StringEqualityOption) bool
	Contains(value string, equalityOptions ...StringEqualityOption) bool
}

type stringValue struct {
	metadata *Metadata
	value    string
}

type stringCheckFunc func(string, string) bool

func (s *stringValue) Metadata() *Metadata {
	return s.metadata
}

func (s *stringValue) Value() string {
	return s.value
}

func (s *stringValue) IsEmpty() bool {
	return s.value == ""
}

func (s *stringValue) EqualTo(value string, equalityOptions ...StringEqualityOption) bool {
	return s.executePredicate(value, func(a, b string) bool { return a == b }, equalityOptions...)
}

func (s *stringValue) NotEqualTo(value string, equalityOptions ...StringEqualityOption) bool {
	return !s.EqualTo(value, equalityOptions...)
}

func (s *stringValue) StartsWith(prefix string, equalityOptions ...StringEqualityOption) bool {
	return s.executePredicate(prefix, strings.HasPrefix, equalityOptions...)
}

func (s *stringValue) EndsWith(suffix string, equalityOptions ...StringEqualityOption) bool {
	return s.executePredicate(suffix, strings.HasSuffix, equalityOptions...)
}

func (s *stringValue) Contains(value string, equalityOptions ...StringEqualityOption) bool {
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
