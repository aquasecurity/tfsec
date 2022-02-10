package ec2

import "github.com/aquasecurity/trivy-config-parsers/types"

type EC2 struct {
	types.Metadata
	Instances []Instance
}
