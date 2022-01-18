package iamgo

import (
	"encoding/json"
	"fmt"
)

type Principals struct {
	All            bool      `json:"-"`
	AWS            StringSet `json:"AWS,omitempty"`
	CanonicalUsers StringSet `json:"CanonicalUser,omitempty"`
	Federated      StringSet `json:"Federated,omitempty"`
	Service        StringSet `json:"Service,omitempty"`
}

func (p *Principals) UnmarshalJSON(b []byte) error {
	if len(b) == 0 {
		return fmt.Errorf("invalid json: unexpected EOF")
	}

	if b[0] == '"' {
		var str string
		if err := json.Unmarshal(b, &str); err != nil {
			return err
		}
		p.All = str == "*"
		return nil
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}

	if _, ok := raw["AWS"]; ok {
		if err := json.Unmarshal(raw["AWS"], &p.AWS); err != nil {
			return err
		}
	}
	if _, ok := raw["CanonicalUser"]; ok {
		if err := json.Unmarshal(raw["CanonicalUser"], &p.CanonicalUsers); err != nil {
			return err
		}
	}
	if _, ok := raw["Federated"]; ok {
		if err := json.Unmarshal(raw["Federated"], &p.Federated); err != nil {
			return err
		}
	}
	if _, ok := raw["Service"]; ok {
		if err := json.Unmarshal(raw["Service"], &p.Service); err != nil {
			return err
		}
	}

	return nil
}

func (p *Principals) MarshalJSON() ([]byte, error) {
	if p.All {
		return []byte(`"*"`), nil
	}

	output := make(map[string]interface{})

	if len(p.AWS) > 0 {
		output["AWS"] = p.AWS
	}
	if len(p.CanonicalUsers) > 0 {
		output["CanonicalUser"] = p.CanonicalUsers
	}
	if len(p.Federated) > 0 {
		output["Federated"] = p.Federated
	}
	if len(p.Service) > 0 {
		output["Service"] = p.Service
	}

	return json.Marshal(output)
}
