package test

import (
	"testing"

	"github.com/tfsec/tfsec/internal/app/tfsec/checks"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

func Test_OCIComputeIpReservation(t *testing.T) {

	var tests = []struct {
		name                  string
		source                string
		mustIncludeResultCode scanner.RuleCode
		mustExcludeResultCode scanner.RuleCode
	}{
		{
			name: "Check OCI compute IP reservation with ip_address_pool = public-ippool",
			source: `
resource "opc_compute_ip_address_reservation" "my-ip-address" {
	ip_address_pool = "public-ippool"
}`,
			mustIncludeResultCode: checks.OCIComputeIpReservation,
		},
		{
			name: "Check OCI compute IP reservation with ip_address_pool = cloud-ippool",
			source: `
resource "opc_compute_ip_address_reservation" "my-ip-address" {
	ip_address_pool = "cloud-ippool"
}`,
			mustExcludeResultCode: checks.OCIComputeIpReservation,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results := scanSource(test.source)
			assertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
