package requirements

type Comparison string

const (
	ComparisonNone               Comparison = ""
	ComparisonEquals             Comparison = "equals"
	ComparisonNotEquals          Comparison = "notequals"
	ComparisonAnyOf              Comparison = "anyof"
	ComparisonNotAnyOf           Comparison = "notanyof"
	ComparisonGreaterThan        Comparison = "greaterthan"
	ComparisonLessThan           Comparison = "lessthan"
	ComparisonGreaterThanOrEqual Comparison = "greaterthanorequal"
	ComparisonLessThanOrEqual    Comparison = "lessthanorequal"
	ComparisonContains           Comparison = "contains"
	ComparisonNotContains        Comparison = "notcontains"
	ComparisonDefined            Comparison = "defined"
	ComparisonNotDefined         Comparison = "notdefined"
	ComparisonIsEmpty            Comparison = "empty"
	ComparisonNotEmpty           Comparison = "notempty"
	ComparisonIsTrue             Comparison = "true"
	ComparisonIsFalse            Comparison = "false"
)

func (c Comparison) Reverse() Comparison {
	switch c {
	case ComparisonEquals:
		return ComparisonNotEquals
	case ComparisonNotEquals:
		return ComparisonEquals
	case ComparisonAnyOf:
		return ComparisonNotAnyOf
	case ComparisonNotAnyOf:
		return ComparisonAnyOf
	case ComparisonGreaterThan:
		return ComparisonLessThanOrEqual
	case ComparisonLessThan:
		return ComparisonGreaterThanOrEqual
	case ComparisonGreaterThanOrEqual:
		return ComparisonLessThan
	case ComparisonLessThanOrEqual:
		return ComparisonGreaterThan
	case ComparisonNotContains:
		return ComparisonContains
	case ComparisonContains:
		return ComparisonNotContains
	case ComparisonDefined:
		return ComparisonNotDefined
	case ComparisonNotDefined:
		return ComparisonDefined
	case ComparisonIsEmpty:
		return ComparisonNotEmpty
	case ComparisonNotEmpty:
		return ComparisonIsEmpty
	case ComparisonIsTrue:
		return ComparisonIsFalse
	case ComparisonIsFalse:
		return ComparisonIsTrue
	default:
		return ComparisonNone
	}
}

func (c Comparison) IsValid() bool {
	return c.Reverse() != ComparisonNone
}
