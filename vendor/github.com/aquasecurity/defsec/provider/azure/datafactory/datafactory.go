package datafactory

import "github.com/aquasecurity/trivy-config-parsers/types"

type DataFactory struct {
	types.Metadata
	DataFactories []Factory
}

type Factory struct {
	types.Metadata
	EnablePublicNetwork types.BoolValue
}
