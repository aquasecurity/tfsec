package compute

import "github.com/aquasecurity/trivy-config-parsers/types"

type Compute struct {
	types.Metadata
	Disks           []Disk
	Networks        []Network
	SSLPolicies     []SSLPolicy
	ProjectMetadata ProjectMetadata
	Instances       []Instance
}
