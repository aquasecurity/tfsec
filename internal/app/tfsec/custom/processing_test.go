package custom

import (
	"encoding/json"
	"fmt"
	"github.com/stretchr/testify/assert"
	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
	"io/ioutil"
	"os"
	"strings"
	"testing"
)

func init() {
	givenCheck(`{
  "checks": [
    {
      "code": "DP006",
      "description": "VPC flow logs must be enabled",
      "requiredTypes": [
        "resource"
      ],
      "requiredLabels": [
        "aws_vpc"
      ],
      "severity": "ERROR",
      "matchSpec": {
        "action": "requiresPresence",
		"name": "aws_flow_log"
      },
      "errorMessage": "VPCs should have an aws_flow_log associated with them",
      "relatedLinks": []
    }
  ]
}
`)
}

func TestRequiresPresenceWithResourcePresent(t *testing.T) {
	scanResults := scanTerraform(t, `
resource "aws_vpc" "main" {
  cidr_block       = "10.0.0.0/16"
  instance_tenancy = "default"

  tags = {
    Name = "main"
  }
}

resource "aws_flow_log" "example" {
  iam_role_arn    = aws_iam_role.example.arn
  log_destination = aws_cloudwatch_log_group.example.arn
  traffic_type    = "ALL"
  vpc_id          = aws_vpc.example.id
}
`)
	assert.Len(t, scanResults, 0)
}
func TestRequiresPresenceWithResourceMissing(t *testing.T) {
	scanResults := scanTerraform(t, `
resource "aws_vpc" "main" {
  cidr_block       = "10.0.0.0/16"
  instance_tenancy = "default"

  tags = {
    Name = "main"
  }
}
`)
	assert.Len(t, scanResults, 1)
}

func givenCheck(jsonContent string) {
	var checksfile ChecksFile
	err := json.NewDecoder(strings.NewReader(jsonContent)).Decode(&checksfile)
	if err != nil {
		panic(err)
	}
	processFoundChecks(checksfile)
}

func scanTerraform(t *testing.T, mainTf string) []scanner.Result {
	dirName, err := ioutil.TempDir("", "tfsec-testing-")
	assert.NoError(t, err)

	err = ioutil.WriteFile(fmt.Sprintf("%s/%s", dirName, "main.tf"), []byte(mainTf), os.ModePerm)
	assert.NoError(t, err)

	blocks, err := parser.New(dirName, "").ParseDirectory()
	assert.NoError(t, err)

	return scanner.New().Scan(blocks, []string{})
}
