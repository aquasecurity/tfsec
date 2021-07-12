package test

import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/rules"
)

func Test_OCIComputeIpReservation(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode string
		mustExcludeResultCode string
	}{
		{
			name: "Rule OCI compute IP reservation with ip_address_pool = public-ippool",
			source: `
resource "opc_compute_ip_address_reservation" "my-ip-address" {
	ip_address_pool = "public-ippool"
}`,
			mustIncludeResultCode: rules.OCIComputeIpReservation,
		},
		{
			name: "Rule OCI compute IP reservation with ip_address_pool = cloud-ippool",
			source: `
resource "opc_compute_ip_address_reservation" "my-ip-address" {
	ip_address_pool = "cloud-ippool"
}`,
			mustExcludeResultCode: rules.OCIComputeIpReservation,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanHCL(test.source, t)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
