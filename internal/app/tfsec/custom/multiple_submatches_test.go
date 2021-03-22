package custom

import (
	"github.com/stretchr/testify/assert"
	"testing"
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
      "severity": "ERROR",
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
	assert.Len(t, scanResults, 0)
}

func TestInstanceMetadataEndpointMissing(t *testing.T) {
	scanResults := scanTerraform(t, `
resource "aws_instance" "bastion" {
}
`)
	assert.Len(t, scanResults, 1)
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
	assert.Len(t, scanResults, 1)
}
