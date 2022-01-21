package oracle

import (
	"github.com/aquasecurity/defsec/provider/oracle"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func Adapt(modules block.Modules) oracle.Oracle {
	return oracle.Oracle{
		Compute: adaptCompute(modules),
	}
}

func adaptCompute(modules block.Modules) oracle.Compute {
	var compute oracle.Compute

	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("opc_compute_ip_address_reservation") {

			addressPoolAttr := resource.GetAttribute("ip_address_pool")
			addressPoolVal := addressPoolAttr.AsStringValueOrDefault("", resource)
			compute.AddressReservations = append(compute.AddressReservations, oracle.AddressReservation{
				Metadata: resource.Metadata(),
				Pool:     addressPoolVal,
			})
		}
	}
	return compute
}
