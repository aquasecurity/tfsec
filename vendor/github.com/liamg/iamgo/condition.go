package iamgo

import (
	"encoding/json"
)

type Conditions []Condition

type Condition struct {
	Operator string
	Key      string
	Value    StringSet
}

func (c *Conditions) UnmarshalJSON(b []byte) error {

	var mapped map[string]map[string]StringSet
	if err := json.Unmarshal(b, &mapped); err != nil {
		return err
	}

	var output []Condition
	for operator, comparison := range mapped {
		for key, value := range comparison {
			output = append(output, Condition{
				Operator: operator,
				Key:      key,
				Value:    value,
			})
		}
	}

	*c = output
	return nil
}

func (c *Conditions) MarshalJSON() ([]byte, error) {

	mapped := make(map[string]map[string]interface{})
	for _, condition := range *c {

		set, ok := mapped[condition.Operator]
		if !ok {
			set = make(map[string]interface{})
		}

		set[condition.Key] = condition.Value
		mapped[condition.Operator] = set
	}

	return json.Marshal(mapped)
}
