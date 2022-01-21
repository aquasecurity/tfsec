package elasticsearch

import (
	"github.com/aquasecurity/defsec/provider/aws/elasticsearch"
	"github.com/aquasecurity/defsec/types"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
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
	nameAttr := resource.GetAttribute("domain_name")
	nameVal := nameAttr.AsStringValueOrDefault("", resource)

	auditEnabled := types.BoolDefault(false, *resource.GetMetadata())
	transitEncryptionVal := types.BoolDefault(false, *resource.GetMetadata())
	atRestEncryptionVal := types.BoolDefault(false, *resource.GetMetadata())
	enforceHTTPSVal := types.BoolDefault(false, *resource.GetMetadata())
	TLSPolicyVal := types.StringDefault("", *resource.GetMetadata())

	if resource.HasChild("log_publishing_options") {
		logOptionsBlock := resource.GetBlock("log_publishing_options")
		enabledAttr := logOptionsBlock.GetAttribute("enabled")
		enabledVal := enabledAttr.AsBoolValueOrDefault(true, logOptionsBlock)

		logTypeAttr := logOptionsBlock.GetAttribute("log_type")
		if logTypeAttr.Equals("AUDIT_LOGS") {
			auditEnabled = enabledVal
		}
	}

	if resource.HasChild("node_to_node_encryption") {
		transitEncryptBlock := resource.GetBlock("node_to_node_encryption")
		enabledAttr := transitEncryptBlock.GetAttribute("enabled")
		transitEncryptionVal = enabledAttr.AsBoolValueOrDefault(false, transitEncryptBlock)
	}

	if resource.HasChild("encrypt_at_rest") {
		atRestEncryptBlock := resource.GetBlock("encrypt_at_rest")
		enabledAttr := atRestEncryptBlock.GetAttribute("enabled")
		atRestEncryptionVal = enabledAttr.AsBoolValueOrDefault(false, atRestEncryptBlock)
	}

	if resource.HasChild("domain_endpoint_options") {
		endpointBlock := resource.GetBlock("domain_endpoint_options")
		enforceHTTPSAttr := endpointBlock.GetAttribute("enforce_https")
		enforceHTTPSVal = enforceHTTPSAttr.AsBoolValueOrDefault(true, endpointBlock)

		TLSPolicyAttr := endpointBlock.GetAttribute("tls_security_policy")
		TLSPolicyVal = TLSPolicyAttr.AsStringValueOrDefault("", endpointBlock)
	}

	return elasticsearch.Domain{
		Metadata:   *resource.GetMetadata(),
		DomainName: nameVal,
		LogPublishing: elasticsearch.LogPublishing{
			AuditEnabled: auditEnabled,
		},
		TransitEncryption: elasticsearch.TransitEncryption{
			Enabled: transitEncryptionVal,
		},
		AtRestEncryption: elasticsearch.AtRestEncryption{
			Enabled: atRestEncryptionVal,
		},
		Endpoint: elasticsearch.Endpoint{
			EnforceHTTPS: enforceHTTPSVal,
			TLSPolicy:    TLSPolicyVal,
		},
	}
}
