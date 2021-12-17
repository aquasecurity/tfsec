package oracle

import "github.com/aquasecurity/defsec/types"

type Oracle struct {
	Compute Compute
}

type Compute struct {
	AddressReservations []AddressReservation
}

type AddressReservation struct {
	Pool types.StringValue // e.g. public-pool
}
