package compute

import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
)

func Test_OCIComputeIpReservation(t *testing.T) {
	expectedCode := "oracle-compute-no-public-ip"

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
			mustIncludeResultCode: expectedCode,
		},
		{
			name: "Rule OCI compute IP reservation with ip_address_pool = cloud-ippool",
			source: `
 resource "opc_compute_ip_address_reservation" "my-ip-address" {
 	ip_address_pool = "cloud-ippool"
 }`,
			mustExcludeResultCode: expectedCode,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			results := testutil.ScanHCL(test.source, t)
			testutil.AssertCheckCode(t, test.mustIncludeResultCode, test.mustExcludeResultCode, results)
		})
	}

}
