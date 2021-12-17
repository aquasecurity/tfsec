package synapse

import "github.com/aquasecurity/defsec/types"

type Synapse struct {
	Workspaces []Workspace
}

type Workspace struct {
	EnableManagedVirtualNetwork types.BoolValue
}
