package dns

import (
	"github.com/aquasecurity/defsec/provider/google/dns"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func Adapt(modules []block.Module) dns.DNS {
	return dns.DNS{}
}
