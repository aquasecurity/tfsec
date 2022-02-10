package oracle

import "github.com/aquasecurity/trivy-config-parsers/types"

type Oracle struct {
	types.Metadata
	Compute Compute
}

type Compute struct {
	types.Metadata
	AddressReservations []AddressReservation
}

type AddressReservation struct {
	types.Metadata
	Pool types.StringValue // e.g. public-pool
}
