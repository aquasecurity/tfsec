package state

import (
	"github.com/aquasecurity/defsec/provider/aws"
	"github.com/aquasecurity/defsec/provider/google"
)

type State struct {
	AWS    aws.AWS
	Google google.Google
}
