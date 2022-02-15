package sam

import "github.com/aquasecurity/trivy-config-parsers/types"

type Application struct {
	types.Metadata
	LocationPath types.StringValue
	Location     Location
}

type Location struct {
	types.Metadata
	ApplicationID   types.StringValue
	SemanticVersion types.StringValue
}
