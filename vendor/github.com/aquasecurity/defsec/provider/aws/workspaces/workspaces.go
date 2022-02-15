package workspaces

import "github.com/aquasecurity/trivy-config-parsers/types"

type WorkSpaces struct {
	types.Metadata
	WorkSpaces []WorkSpace
}

type WorkSpace struct {
	types.Metadata
	RootVolume Volume
	UserVolume Volume
}

type Volume struct {
	types.Metadata
	Encryption Encryption
}

type Encryption struct {
	types.Metadata
	Enabled types.BoolValue
}
