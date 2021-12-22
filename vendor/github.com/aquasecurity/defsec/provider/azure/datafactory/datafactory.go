package datafactory

import "github.com/aquasecurity/defsec/types"

type DataFactory struct {
	DataFactories []Factory
}

type Factory struct {
	EnablePublicNetwork types.BoolValue
}
