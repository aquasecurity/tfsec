package compute

import "github.com/aquasecurity/defsec/types"

type Compute struct {
	Instances []Instance
}

type Instance struct {
	UserData types.StringValue // not b64 encoded pls
}
