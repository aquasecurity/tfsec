package iam

import "github.com/aquasecurity/defsec/types"

type IAM struct {
}

type Member struct {
	Member                types.StringValue
	Role                  types.StringValue
	DefaultServiceAccount types.BoolValue
}

type Binding struct {
	Members []types.StringValue
	Role    types.StringValue
}
