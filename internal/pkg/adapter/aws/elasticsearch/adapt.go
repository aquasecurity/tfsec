package elasticsearch

import (
	"github.com/aquasecurity/defsec/provider/aws/elasticsearch"
	"github.com/aquasecurity/defsec/types"
	"github.com/aquasecurity/tfsec/internal/pkg/block"
)

func Adapt(modules block.Modules) elasticsearch.Elasticsearch {
	return elasticsearch.Elasticsearch{
		Domains: adaptDomains(modules),
	}
}

func adaptDomains(modules block.Modules) []elasticsearch.Domain {
	var domains []elasticsearch.Domain
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_elasticsearch_domain") {
			domains = append(domains, adaptDomain(resource))
		}
	}
	return domains
}

func adaptDomain(resource *block.Block) elasticsearch.Domain {
	domain := elasticsearch.Domain{
		Metadata:   resource.Metadata(),
		DomainName: types.StringDefault("", resource.Metadata()),
		LogPublishing: elasticsearch.LogPublishing{
			Metadata:     resource.Metadata(),
			AuditEnabled: types.BoolDefault(false, resource.Metadata()),
		},
		TransitEncryption: elasticsearch.TransitEncryption{
			Metadata: resource.Metadata(),
			Enabled:  types.BoolDefault(false, resource.Metadata()),
		},
		AtRestEncryption: elasticsearch.AtRestEncryption{
			Metadata: resource.Metadata(),
			Enabled:  types.BoolDefault(false, resource.Metadata()),
		},
		Endpoint: elasticsearch.Endpoint{
			Metadata:     resource.Metadata(),
			EnforceHTTPS: types.BoolDefault(false, resource.Metadata()),
			TLSPolicy:    types.StringDefault("", resource.Metadata()),
		},
	}

	nameAttr := resource.GetAttribute("domain_name")
	domain.DomainName = nameAttr.AsStringValueOrDefault("", resource)

	for _, logOptionsBlock := range resource.GetBlocks("log_publishing_options") {
		domain.LogPublishing.Metadata = logOptionsBlock.Metadata()
		enabledAttr := logOptionsBlock.GetAttribute("enabled")
		enabledVal := enabledAttr.AsBoolValueOrDefault(true, logOptionsBlock)
		logTypeAttr := logOptionsBlock.GetAttribute("log_type")
		if logTypeAttr.Equals("AUDIT_LOGS") {
			domain.LogPublishing.AuditEnabled = enabledVal
		}
	}

	if transitEncryptBlock := resource.GetBlock("node_to_node_encryption"); transitEncryptBlock.IsNotNil() {
		enabledAttr := transitEncryptBlock.GetAttribute("enabled")
		domain.TransitEncryption.Metadata = transitEncryptBlock.Metadata()
		domain.TransitEncryption.Enabled = enabledAttr.AsBoolValueOrDefault(false, transitEncryptBlock)
	}

	if atRestEncryptBlock := resource.GetBlock("encrypt_at_rest"); atRestEncryptBlock.IsNotNil() {
		enabledAttr := atRestEncryptBlock.GetAttribute("enabled")
		domain.AtRestEncryption.Metadata = atRestEncryptBlock.Metadata()
		domain.AtRestEncryption.Enabled = enabledAttr.AsBoolValueOrDefault(false, atRestEncryptBlock)
	}

	if endpointBlock := resource.GetBlock("domain_endpoint_options"); endpointBlock.IsNotNil() {
		domain.Endpoint.Metadata = endpointBlock.Metadata()
		enforceHTTPSAttr := endpointBlock.GetAttribute("enforce_https")
		domain.Endpoint.EnforceHTTPS = enforceHTTPSAttr.AsBoolValueOrDefault(true, endpointBlock)
		TLSPolicyAttr := endpointBlock.GetAttribute("tls_security_policy")
		domain.Endpoint.TLSPolicy = TLSPolicyAttr.AsStringValueOrDefault("", endpointBlock)
	}

	return domain
}
