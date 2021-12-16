package apigateway

import (
	"github.com/aquasecurity/defsec/provider/aws/apigateway"
	"github.com/aquasecurity/defsec/types"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func adaptDomainNamesV1(modules []block.Module) []apigateway.DomainName {

	var domainNames []apigateway.DomainName

	for _, module := range modules {
		for _, nameBlock := range module.GetResourcesByType("aws_api_gateway_domain_name") {
			var domainName apigateway.DomainName
			domainName.Metadata = nameBlock.Metadata()
			domainName.Version = types.Int(1, nameBlock.Metadata())

			if name := nameBlock.GetAttribute("domain_name"); name.IsString() {
				domainName.Name = name.AsStringValue(true)
			} else {
				domainName.Name = types.StringDefault("", nameBlock.Metadata())
			}

			if policy := nameBlock.GetAttribute("security_policy"); policy.IsString() {
				domainName.SecurityPolicy = policy.AsStringValue(true)
			} else {
				domainName.SecurityPolicy = types.StringDefault("TLS_1_0", nameBlock.Metadata())
			}

			domainNames = append(domainNames, domainName)
		}
	}

	return domainNames
}
