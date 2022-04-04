package custom

import (
	"testing"

	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func init() {
	givenCheck(`{
  "checks": [
    {
      "code": "CUSTOM",
      "description": "Instance Metadata Service V2 is required",
      "requiredTypes": [
        "resource"
      ],
      "requiredLabels": [
        "aws_instance"
      ],
      "severity": "HIGH",
      "matchSpec": {
        "name": "metadata_options",
        "action": "isPresent",
        "subMatch": {
          "action": "and",
          "predicateMatchSpec": [
            {
              "name": "http_endpoint",
              "action": "equals",
              "value": "enabled"
            },
            {
              "name": "http_put_response_hop_limit",
              "action": "equals",
              "value": 1
            },
            {
              "name": "http_tokens",
              "action": "equals",
              "value": "required"
            }
          ]
        }
      }
    }
  ]
}
`)
}

func TestInstanceMetadataEndpointPresent(t *testing.T) {
	scanResults := scanTerraform(t, `
resource "aws_instance" "bastion" {
  metadata_options {
    http_endpoint               = "enabled"
    http_put_response_hop_limit = 1
    http_tokens                 = "required"
  }
}
`)
	customResults := filterCustomResults(scanResults)
	assert.Len(t, customResults.GetFailed(), 0)
}

func TestInstanceMetadataEndpointMissing(t *testing.T) {
	scanResults := scanTerraform(t, `
resource "aws_instance" "bastion" {
}
`)
	customResults := filterCustomResults(scanResults)
	assert.Len(t, customResults, 1)
}

func TestOneSubmatchHasWrongValue(t *testing.T) {
	scanResults := scanTerraform(t, `
resource "aws_instance" "bastion" {
  metadata_options {
    http_endpoint               = "enabled"
    http_put_response_hop_limit = 1
    http_tokens                 = "definitely-wrong-not-required"
  }
}
`)

	customResults := filterCustomResults(scanResults)
	assert.Len(t, customResults, 1)
}

func filterCustomResults(scanResults []scan.Result) scan.Results {
	var customResults []scan.Result
	for _, result := range scanResults {
		if result.Rule().Provider.DisplayName() == providers.CustomProvider.DisplayName() {
			customResults = append(customResults, result)
		}
	}
	return customResults
}
