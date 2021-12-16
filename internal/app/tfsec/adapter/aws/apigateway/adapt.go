package apigateway

import (
	"github.com/aquasecurity/defsec/provider/aws/apigateway"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func Adapt(modules []block.Module) apigateway.APIGateway {
	return apigateway.APIGateway{
		APIs:        adaptAPIs(modules),
		DomainNames: adaptDomainNames(modules),
	}
}

func adaptAPIs(modules []block.Module) []apigateway.API {
	return append(adaptAPIsV1(modules), adaptAPIsV2(modules)...)
}

func adaptDomainNames(modules []block.Module) []apigateway.DomainName {
	return append(adaptDomainNamesV1(modules), adaptDomainNamesV2(modules)...)
}
