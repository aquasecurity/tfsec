package vpc

import (
	"github.com/aquasecurity/defsec/provider/aws/vpc"
	"github.com/aquasecurity/defsec/types"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func Adapt(modules []block.Module) vpc.VPC {
	return vpc.VPC{
		DefaultVPCs:    adaptDefaultVPCs(modules),
		SecurityGroups: adaptSecurityGroups(modules),
		NetworkACLs:    adaptNetworkACLs(modules),
	}
}

func adaptDefaultVPCs(modules []block.Module) []vpc.DefaultVPC {
	var defaultVPCs []vpc.DefaultVPC
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_default_vpc") {
			defaultVPCs = append(defaultVPCs, vpc.DefaultVPC{
				Metadata: *resource.GetMetadata(),
			})
		}
	}
	return defaultVPCs
}

func adaptSecurityGroups(modules []block.Module) []vpc.SecurityGroup {
	var securityGroups []vpc.SecurityGroup
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_security_group") {
			securityGroups = append(securityGroups, adaptSecurityGroup(resource, module))
		}
	}
	return securityGroups
}

func adaptNetworkACLs(modules []block.Module) []vpc.NetworkACL {
	var networkACLs []vpc.NetworkACL
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("aws_network_acl") {
			networkACLs = append(networkACLs, adaptNetworkACL(resource, module))
		}
	}
	return networkACLs
}

func adaptSecurityGroup(resource block.Block, module block.Module) vpc.SecurityGroup {
	var ingressRules []vpc.SecurityGroupRule
	var egressRules []vpc.SecurityGroupRule

	descriptionAttr := resource.GetAttribute("description")
	descriptionVal := descriptionAttr.AsStringValueOrDefault("Managed by Terraform", resource)

	ingressBlocks := resource.GetBlocks("ingress")
	for _, ingressBlock := range ingressBlocks {
		ingressRules = append(ingressRules, adaptSGRule(ingressBlock, module))
	}

	egressBlocks := resource.GetBlocks("egress")
	for _, egressBlock := range egressBlocks {
		egressRules = append(egressRules, adaptSGRule(egressBlock, module))
	}

	rulesBlocks := module.GetReferencingResources(resource, "aws_security_group_rule", "security_group_id")
	for _, ruleBlock := range rulesBlocks {
		if ruleBlock.GetAttribute("type").Equals("ingress") {
			ingressRules = append(ingressRules, adaptSGRule(ruleBlock, module))
		} else if ruleBlock.GetAttribute("type").Equals("egress") {
			egressRules = append(egressRules, adaptSGRule(ruleBlock, module))
		}
	}

	return vpc.SecurityGroup{
		Metadata:     *resource.GetMetadata(),
		Description:  descriptionVal,
		IngressRules: ingressRules,
		EgressRules:  egressRules,
	}
}

func adaptSGRule(resource block.Block, module block.Module) vpc.SecurityGroupRule {
	ruleDescAttr := resource.GetAttribute("description")
	ruleDescVal := ruleDescAttr.AsStringValueOrDefault("", resource)

	var cidrs []types.StringValue

	cidrBlocks := resource.GetAttribute("cidr_blocks")
	ipv6cidrBlocks := resource.GetAttribute("ipv6_cidr_blocks")
	varBlocks := module.GetBlocks().OfType("variable")

	for _, vb := range varBlocks {
		if cidrBlocks.IsNotNil() && cidrBlocks.ReferencesBlock(vb) {
			cidrBlocks = vb.GetAttribute("default")
		}
		if ipv6cidrBlocks.IsNotNil() && ipv6cidrBlocks.ReferencesBlock(vb) {
			ipv6cidrBlocks = vb.GetAttribute("default")
		}
	}

	if cidrBlocks.IsNotNil() && cidrBlocks.IsIterable() {
		cidrsList := cidrBlocks.ValueAsStrings()
		for _, cidr := range cidrsList {
			cidrs = append(cidrs, types.String(cidr, *cidrBlocks.GetMetadata()))
		}
	} else {
		cidrs = append(cidrs, cidrBlocks.AsStringValueOrDefault("", resource))
	}

	if ipv6cidrBlocks.IsNotNil() && ipv6cidrBlocks.IsIterable() {
		cidrsList := ipv6cidrBlocks.ValueAsStrings()
		for _, cidr := range cidrsList {
			cidrs = append(cidrs, types.String(cidr, *ipv6cidrBlocks.GetMetadata()))
		}
	} else {
		cidrs = append(cidrs, ipv6cidrBlocks.AsStringValueOrDefault("", resource))
	}

	return vpc.SecurityGroupRule{
		Metadata:    *resource.GetMetadata(),
		Description: ruleDescVal,
		CIDRs:       cidrs,
	}
}

func adaptNetworkACL(resource block.Block, module block.Module) vpc.NetworkACL {
	var networkRules []vpc.NetworkACLRule
	rulesBlocks := module.GetReferencingResources(resource, "aws_network_acl_rule", "network_acl_id")
	for _, ruleBlock := range rulesBlocks {
		networkRules = append(networkRules, adaptNetworkACLRule(ruleBlock))
	}
	return vpc.NetworkACL{
		Metadata: *resource.GetMetadata(),
		Rules:    networkRules,
	}
}

func adaptNetworkACLRule(resource block.Block) vpc.NetworkACLRule {
	var cidrs []types.StringValue

	typeVal := types.StringDefault("ingress", *resource.GetMetadata())

	egressAtrr := resource.GetAttribute("egress")
	if egressAtrr.IsTrue() {
		typeVal = types.String("egress", *resource.GetMetadata())
	}

	actionAttr := resource.GetAttribute("rule_action")
	actionVal := actionAttr.AsStringValueOrDefault("", resource)

	protocolAtrr := resource.GetAttribute("protocol")
	protocolVal := protocolAtrr.AsStringValueOrDefault("-1", resource)

	cidrAttr := resource.GetAttribute("cidr_block")
	ipv4cidrAttr := resource.GetAttribute("ipv6_cidr_block")
	cidrs = append(cidrs, cidrAttr.AsStringValueOrDefault("", resource))
	cidrs = append(cidrs, ipv4cidrAttr.AsStringValueOrDefault("", resource))

	return vpc.NetworkACLRule{
		Metadata: *resource.GetMetadata(),
		Type:     typeVal,
		Action:   actionVal,
		Protocol: protocolVal,
		CIDRs:    cidrs,
	}
}
