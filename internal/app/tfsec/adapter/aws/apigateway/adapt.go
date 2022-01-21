package apigateway

import (
	"github.com/aquasecurity/defsec/provider/aws/apigateway"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func Adapt(modules block.Modules) apigateway.APIGateway {
	return apigateway.APIGateway{
		APIs:        adaptAPIs(modules),
		DomainNames: adaptDomainNames(modules),
	}
}

func adaptAPIs(modules block.Modules) []apigateway.API {
	return append(adaptAPIsV1(modules), adaptAPIsV2(modules)...)
}

func adaptDomainNames(modules block.Modules) []apigateway.DomainName {
	return append(adaptDomainNamesV1(modules), adaptDomainNamesV2(modules)...)
}
