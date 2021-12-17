package sam

import "github.com/aquasecurity/defsec/types"

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

func (a *Application) GetMetadata() *types.Metadata {
	return &a.Metadata
}

func (a *Application) GetRawValue() interface{} {
	return nil
}

func (a *Location) GetMetadata() *types.Metadata {
	return &a.Metadata
}

func (a *Location) GetRawValue() interface{} {
	return nil
}
