package iamgo

import "encoding/json"

func Parse(policy []byte) (*Document, error) {
	var doc Document
	if err := json.Unmarshal(policy, &doc); err != nil {
		return nil, err
	}
	return &doc, nil
}

func ParseString(policy string) (*Document, error) {
	return Parse([]byte(policy))
}
