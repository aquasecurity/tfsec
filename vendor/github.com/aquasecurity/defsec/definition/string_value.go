package definition

import "strings"

type StringCheckFunc func(string, string) bool
type StringEqualityOption int

const (
	IgnoreCase StringEqualityOption = iota
)

type StringValue struct {
	*Metadata
	Value string
}

func (s *StringValue) EqualTo(value string, equalityOptions ...StringEqualityOption) bool {
	return s.executePredicate(value, func(a, b string) bool { return a == b }, equalityOptions...)
}

func (s *StringValue) NotEqualTo(value string, equalityOptions ...StringEqualityOption) bool {
	return !s.EqualTo(value, equalityOptions...)
}

func (s *StringValue) StartsWith(prefix string, equalityOptions ...StringEqualityOption) bool {
	return s.executePredicate(prefix, strings.HasPrefix, equalityOptions...)
}

func (s *StringValue) EndsWith(suffix string, equalityOptions ...StringEqualityOption) bool {
	return s.executePredicate(suffix, strings.HasSuffix, equalityOptions...)
}

func (s *StringValue) Contains(value string, equalityOptions ...StringEqualityOption) bool {
	return s.executePredicate(value, strings.Contains, equalityOptions...)
}

func (s *StringValue) executePredicate(value string, fn StringCheckFunc, equalityOptions ...StringEqualityOption) bool {
	subjectString := s.Value
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

func EmptyStringValue(r Range) StringValue {
	return StringValue{
		Metadata: NewMetadata(r),
	}

}
