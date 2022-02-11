package eks

import "github.com/aquasecurity/trivy-config-parsers/types"

type EKS struct {
	types.Metadata
	Clusters []Cluster
}

type Cluster struct {
	types.Metadata
	Logging             Logging
	Encryption          Encryption
	PublicAccessEnabled types.BoolValue
	PublicAccessCIDRs   []types.StringValue
}

type Logging struct {
	types.Metadata
	API               types.BoolValue
	Audit             types.BoolValue
	Authenticator     types.BoolValue
	ControllerManager types.BoolValue
	Scheduler         types.BoolValue
}

type Encryption struct {
	types.Metadata
	Secrets  types.BoolValue
	KMSKeyID types.StringValue
}
