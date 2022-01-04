package dns

import "github.com/aquasecurity/defsec/types"

type DNS struct {
	ManagedZones []ManagedZone
}

type ManagedZone struct {
	DNSSec DNSSec
}

type DNSSec struct {
	Enabled         types.BoolValue
	DefaultKeySpecs KeySpecs
}

type KeySpecs struct {
	KeySigningKey  Key
	ZoneSigningKey Key
}

type Key struct {
	Algorithm types.StringValue
}
