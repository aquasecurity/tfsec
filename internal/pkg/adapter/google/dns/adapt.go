package dns

import (
	"github.com/aquasecurity/defsec/provider/google/dns"
	"github.com/aquasecurity/defsec/types"
	"github.com/aquasecurity/tfsec/internal/pkg/block"
)

func Adapt(modules block.Modules) dns.DNS {
	return dns.DNS{
		ManagedZones: adaptManagedZones(modules),
	}
}

func adaptManagedZones(modules block.Modules) []dns.ManagedZone {
	var managedZones []dns.ManagedZone
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("google_dns_managed_zone") {
			managedZone := adaptManagedZone(resource)
			for _, data := range module.GetDatasByType("google_dns_keys") {
				managedZone.DNSSec.DefaultKeySpecs = adaptKeySpecs(data)
			}
			managedZones = append(managedZones, managedZone)
		}
	}
	return managedZones
}

func adaptManagedZone(resource *block.Block) dns.ManagedZone {

	zone := dns.ManagedZone{
		Metadata: resource.Metadata(),
		DNSSec: dns.DNSSec{
			Metadata: resource.Metadata(),
			Enabled:  types.BoolDefault(false, resource.Metadata()),
			DefaultKeySpecs: dns.KeySpecs{
				Metadata: resource.Metadata(),
				KeySigningKey: dns.Key{
					Metadata:  resource.Metadata(),
					Algorithm: types.StringDefault("", resource.Metadata()),
				},
				ZoneSigningKey: dns.Key{
					Metadata:  resource.Metadata(),
					Algorithm: types.StringDefault("", resource.Metadata()),
				},
			},
		},
	}

	if resource.HasChild("dnssec_config") {
		DNSSecBlock := resource.GetBlock("dnssec_config")

		stateAttr := DNSSecBlock.GetAttribute("state")
		if stateAttr.Equals("on") {
			zone.DNSSec.Enabled = types.Bool(true, DNSSecBlock.Metadata())
		} else if stateAttr.Equals("off") || stateAttr.Equals("transfer") {
			zone.DNSSec.Enabled = types.Bool(false, DNSSecBlock.Metadata())
		}

		if DNSSecBlock.HasChild("default_key_specs") {
			DefaultKeySpecsBlock := DNSSecBlock.GetBlock("default_key_specs")

			algorithmAttr := DefaultKeySpecsBlock.GetAttribute("algorithm")
			algorithmVal := algorithmAttr.AsStringValueOrDefault("", DefaultKeySpecsBlock)

			keyTypeAttr := DefaultKeySpecsBlock.GetAttribute("key_type")
			if keyTypeAttr.Equals("keySigning") {
				zone.DNSSec.DefaultKeySpecs.KeySigningKey.Algorithm = algorithmVal
			} else if keyTypeAttr.Equals("zoneSigning") {
				zone.DNSSec.DefaultKeySpecs.ZoneSigningKey.Algorithm = algorithmVal
			}
		}
	}
	return zone
}

func adaptKeySpecs(resource *block.Block) dns.KeySpecs {
	keySpecs := dns.KeySpecs{
		Metadata: resource.Metadata(),
		KeySigningKey: dns.Key{
			Metadata:  resource.Metadata(),
			Algorithm: types.String("", resource.Metadata()),
		},
		ZoneSigningKey: dns.Key{
			Metadata:  resource.Metadata(),
			Algorithm: types.String("", resource.Metadata()),
		},
	}
	KeySigningKeysBlock := resource.GetBlock("key_signing_keys")
	if KeySigningKeysBlock.IsNotNil() {
		algorithmAttr := KeySigningKeysBlock.GetAttribute("algorithm")
		keySpecs.KeySigningKey.Algorithm = algorithmAttr.AsStringValueOrDefault("", KeySigningKeysBlock)
	}

	ZoneSigningKeysBlock := resource.GetBlock("zone_signing_keys")
	if ZoneSigningKeysBlock.IsNotNil() {
		algorithmAttr := ZoneSigningKeysBlock.GetAttribute("algorithm")
		keySpecs.ZoneSigningKey.Algorithm = algorithmAttr.AsStringValueOrDefault("", ZoneSigningKeysBlock)
	}

	return keySpecs
}
