package iam

import (
	"encoding/json"
	"fmt"

	"github.com/aquasecurity/defsec/types"
)

func ParsePolicyDocument(policy []byte, metadata types.Metadata) (*PolicyDocument, error) {
	var doc PolicyDocument
	if err := json.Unmarshal(policy, &doc); err != nil {
		return nil, err
	}
	doc.metadata = metadata
	return &doc, nil
}

type PolicyDocument struct {
	metadata   types.Metadata
	Statements []PolicyDocumentStatement `json:"Statement"`
}

func (p PolicyDocument) GetMetadata() *types.Metadata {
	return &p.metadata
}

func (p PolicyDocument) GetRawValue() interface{} {
	return nil
}

type PolicyDocumentStatement struct {
	Effect    string                    `json:"Effect"`
	Action    awsIAMPolicyDocumentValue `json:"Action"`
	Resource  awsIAMPolicyDocumentValue `json:"Resource,omitempty"`
	Principal awsIAMPolicyPrincipal     `json:"Principal,omitempty"`
}

type awsIAMPolicyPrincipal struct {
	AWS     []string
	Service []string
}

// AWS allows string or []string as value, we convert everything to []string to avoid casting
type awsIAMPolicyDocumentValue []string

func (value *awsIAMPolicyPrincipal) UnmarshalJSON(b []byte) error {

	var raw interface{}
	err := json.Unmarshal(b, &raw)
	if err != nil {
		return err
	}

	//  value can be string or []string, convert everything to []string
	switch v := raw.(type) {
	case map[string]interface{}:
		for key, each := range v {
			switch raw := each.(type) {
			case string:
				if key == "Service" {
					value.Service = append(value.Service, raw)
				} else {
					value.AWS = append(value.AWS, raw)
				}
			case []interface{}, []string:
				if key == "Service" {
					for _, r := range raw.([]interface{}) {
						value.Service = append(value.Service, r.(string))
					}

				} else {
					for _, r := range raw.([]interface{}) {
						value.AWS = append(value.AWS, r.(string))
					}
				}
			}
		}
	case string:
		value.AWS = []string{v}
	case []interface{}:
		for _, item := range v {
			value.AWS = append(value.AWS, fmt.Sprintf("%v", item))
		}
	case []string:
		for _, item := range v {
			value.AWS = append(value.AWS, item)
		}
	default:
		return fmt.Errorf("invalid %s value element: allowed is only string or []string", value)
	}

	return nil
}

func (value *awsIAMPolicyDocumentValue) UnmarshalJSON(b []byte) error {

	var raw interface{}
	err := json.Unmarshal(b, &raw)
	if err != nil {
		return err
	}

	var p []string
	//  value can be string or []string, convert everything to []string
	switch v := raw.(type) {
	case string:
		p = []string{v}
	case []interface{}:
		var items []string
		for _, item := range v {
			items = append(items, fmt.Sprintf("%v", item))
		}
		p = items
	default:
		return fmt.Errorf("invalid %s value element: allowed is only string or []string", value)
	}

	*value = p
	return nil
}
