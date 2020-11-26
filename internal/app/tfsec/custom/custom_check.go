package custom

import (
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

type MatchType string
type CheckAction string

var ValidCheckActions = []CheckAction{
	InModule,
	IsPresent,
	NotPresent,
	IsEmpty,
	StartsWith,
	EndsWith,
	Contains,
	NotContains,
	Equals,
	LessThan,
	LessThanOrEqualTo,
	GreaterThan,
	GreaterThanOrEqualTo,
	RegexMatches,
	RequiresPresence,
	IsAny,
	IsNone,
}

// InModule checks that the block is part of a module
const InModule CheckAction = "inModule"

// IsPresent checks that the named child is present in the block
const IsPresent CheckAction = "isPresent"

// IsEmpty checks that the named attribute value is empty
const IsEmpty CheckAction = "isEmpty"

// NotPresent checks that the named child is absent in the block
const NotPresent CheckAction = "notPresent"

// StartsWith checks that the named child attribute has a value that starts with the check value
const StartsWith CheckAction = "startsWith"

// EndsWith checks that the named child attribute has a value that ends with the check value
const EndsWith CheckAction = "endsWith"

// Contains checks that the named child attribute has a value in the map, list or attribute
const Contains CheckAction = "contains"

// NotContains checks that the named child attribute does not have a value in the map, list or attribute
const NotContains CheckAction = "notContains"

// Contains checks that the named child attribute has a value equal to the check value
const Equals CheckAction = "equals"

// RegexMatches checks that the named attribute has a value that matches the regex
const RegexMatches CheckAction = "regexMatches"

// IsAny checks that the named attribute value can be found in the provided slice
const IsAny CheckAction = "isAny"

// IsNone checks that the named attribute value cannot be found in the provided slice
const IsNone CheckAction = "isNone"

// LessThan checks that the named attribute value is less than the check value
const LessThan CheckAction = "lessThan"

// LessThanOrEqualTo checks that the named attribute value is less than or equal to the check value
const LessThanOrEqualTo CheckAction = "lessThanOrEqualTo"

// GreaterThan checks that the named attribute value is greater than the check value
const GreaterThan CheckAction = "greaterThan"

// GreaterThanOrEqualTo checks that the named attribute value is greater than or equal to the check value
const GreaterThanOrEqualTo CheckAction = "greaterThanOrEqualTo"

// RequiresPresence checks that a second resource is present
const RequiresPresence CheckAction = "requiresPresence"

// MatchSpec specifies the checks that should be performed
type MatchSpec struct {
	Name            string      `json:"name,omitempty" yaml:"name,omitempty"`
	MatchValue      interface{} `json:"value,omitempty" yaml:"value,omitempty"`
	Action          CheckAction `json:"action,omitempty" yaml:"action,omitempty"`
	SubMatch        *MatchSpec  `json:"subMatch,omitempty" yaml:"subMatch,omitempty"`
	IgnoreUndefined bool        `json:"ignoreUndefined,omitempty" yaml:"ignoreUndefined,omitempty"`
}

//Check specifies the check definition represented in json/yaml
type Check struct {
	Code           scanner.RuleCode    `json:"code" yaml:"code"`
	Description    scanner.RuleSummary `json:"description" yaml:"description"`
	RequiredTypes  []string            `json:"requiredTypes" yaml:"requiredTypes"`
	RequiredLabels []string            `json:"requiredLabels" yaml:"requiredLabels"`
	Severity       scanner.Severity    `json:"severity" yaml:"severity"`
	ErrorMessage   string              `json:"errorMessage,omitempty" yaml:"errorMessage,omitempty"`
	MatchSpec      *MatchSpec          `json:"matchSpec" yaml:"matchSpec"`
	RelatedLinks   []string            `json:"relatedLinks,omitempty" yaml:"relatedLinks,omitempty"`
}

func (action *CheckAction) isValid() bool {
	for _, checkAction := range ValidCheckActions {
		if checkAction == *action {
			return true
		}
	}
	return false
}
