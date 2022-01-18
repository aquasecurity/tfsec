package iamgo

import (
	"encoding/json"
	"fmt"
)

type Statement struct {
	Sid          string      `json:"Sid,omitempty"`
	Effect       Effect      `json:"Effect"`
	Principal    *Principals `json:"Principal,omitempty"`
	NotPrincipal *Principals `json:"NotPrincipal,omitempty"`
	Action       StringSet   `json:"Action,omitempty"`
	NotAction    StringSet   `json:"NotAction,omitempty"`
	Resource     StringSet   `json:"Resource,omitempty"`
	NotResource  StringSet   `json:"NotResource,omitempty"`
	Condition    Conditions  `json:"Condition,omitempty"`
}

type Statements []Statement

func (v *Statements) UnmarshalJSON(b []byte) error {

	if len(b) == 0 {
		return fmt.Errorf("invalid json: unexpected EOF")
	}

	// unmarshal slice of statements
	if b[0] == '[' {
		var output []Statement
		if err := json.Unmarshal(b, &output); err != nil {
			return err
		}
		*v = output
		return nil
	}

	// unmarshal single statement
	var statement Statement
	if err := json.Unmarshal(b, &statement); err != nil {
		return err
	}
	*v = []Statement{statement}
	return nil
}

type StringSet []string

func (v *StringSet) UnmarshalJSON(b []byte) error {
	var raw interface{}
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	switch actual := raw.(type) {
	case []string:
		*v = actual
	case []interface{}:
		var output []string
		for _, raw := range actual {
			output = append(output, fmt.Sprintf("%s", raw))
		}
		*v = output
	case string:
		*v = []string{actual}
	default:
		return fmt.Errorf("cannot use %T type for multi-value JSON field", actual)
	}
	return nil
}
