package custom

import (
	"context"
	"encoding/json"
	"io/fs"
	"strings"
	"testing"

	"github.com/aquasecurity/defsec/pkg/scan"
	scanner "github.com/aquasecurity/defsec/pkg/scanners/terraform"
	"github.com/aquasecurity/defsec/pkg/scanners/terraform/parser"
	"github.com/liamg/memoryfs"

	"github.com/aquasecurity/defsec/pkg/terraform"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
      "severity": "HIGH",
      "matchSpec": {
        "action": "requiresPresence",
		"name": "aws_flow_log",
		"subMatch": {
		  "action": "isPresent",
		  "name": "log_destination"
		}
      },
      "errorMessage": "VPCs should have an aws_flow_log associated with them",
      "relatedLinks": []
    }
  ]
}
`)
}

var testOrMatchSpec = MatchSpec{
	Action: "or",
	PredicateMatchSpec: []MatchSpec{
		{
			Name:   "name",
			Action: "isPresent",
		},
		{
			Name:   "description",
			Action: "isPresent",
		},
	},
}

var testAndMatchSpec = MatchSpec{
	Action: "and",
	PredicateMatchSpec: []MatchSpec{
		{
			Name:   "name",
			Action: "isPresent",
		},
		{
			Name:   "description",
			Action: "isPresent",
		},
	},
}

var testNestedMatchSpec = MatchSpec{
	Action: "and",
	PredicateMatchSpec: []MatchSpec{
		{
			Name:       "virtualization_type",
			Action:     "equals",
			MatchValue: "paravirtual",
		},
		{
			Action: "or",
			PredicateMatchSpec: []MatchSpec{
				{
					Name:   "image_location",
					Action: "isPresent",
				},
				{
					Name:   "kernel_id",
					Action: "isPresent",
				},
			},
		},
	},
}

var testNotMatchSpec = MatchSpec{
	Action: "not",
	PredicateMatchSpec: []MatchSpec{
		{
			Name:       "virtualization_type",
			Action:     "equals",
			MatchValue: "paravirtual",
		},
	},
}

var testPreConditionCheck = MatchSpec{
	Action:     "equals",
	Name:       "name",
	MatchValue: "test-name",
	PreConditions: []MatchSpec{
		{
			Action:     "equals",
			Name:       "id",
			MatchValue: "test-id",
		},
	},
}

var testAssignVariableMatchSpec = MatchSpec{
	Action: "and",
	PredicateMatchSpec: []MatchSpec{
		{
			Name:           "bucket",
			Action:         "isPresent",
			AssignVariable: "TFSEC_VAR_BUCKET_NAME",
		},
		{
			Name:   "lifecycle_rule",
			Action: "isPresent",
			SubMatch: &MatchSpec{
				Name:       "id",
				Action:     "startsWith",
				MatchValue: "TFSEC_VAR_BUCKET_NAME",
			},
		},
	},
}

var testSubMatchOnesSource = `
resource "aws_dynamodb_table" "example" {
  name     = "example"
  hash_key = "TestTableHashKey"

  attribute {
    name = "TestTableHashKey"
    type = "S"
  }

  replica {
    region_name = "us-east-2"
  }

  replica {
    region_name = "eu-west-2"
  }
}
`

func assertResultsContainID(t *testing.T, scanResults scan.Results, id string) {
	for _, result := range scanResults {
		if result.Rule().ShortCode == id {
			return
		}
	}
	t.Fatalf("Expected results to contain %s", id)
}

func assertResultsDoNotContainID(t *testing.T, scanResults scan.Results, id string) {
	for _, result := range scanResults {
		if result.Rule().AVDID == id {
			t.Fatalf("Expected results not to contain %s", id)
		}
	}
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
	assertResultsDoNotContainID(t, scanResults, "DP006")
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
	assertResultsContainID(t, scanResults, "DP006")
}

func TestRequiresPresenceWithSubMatchFailing(t *testing.T) {
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
  traffic_type    = "ALL"
  vpc_id          = aws_vpc.example.id
}
`)
	assertResultsContainID(t, scanResults, "DP006")
}

func TestOrMatchFunction(t *testing.T) {

	var tests = []struct {
		name               string
		source             string
		predicateMatchSpec MatchSpec
		expected           bool
	}{
		{
			name: "check `or` match function with no true evaluation",
			source: `
resource "aws_ami" "example" {
}
`,
			predicateMatchSpec: testOrMatchSpec,
			expected:           false,
		},
		{
			name: "check `or` match function with a single true evaluation",
			source: `
resource "aws_ami" "example" {
	name = "placeholder-name"
}
`,
			predicateMatchSpec: testOrMatchSpec,
			expected:           true,
		},
		{
			name: "check `or` match function with all true evaluation",
			source: `
resource "aws_ami" "example" {
	name = "placeholder-name"
	description = "this is a description."
}
`,
			predicateMatchSpec: testOrMatchSpec,
			expected:           true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			block := parseFromSource(t, test.source)[0].GetBlocks()[0]
			result := evalMatchSpec(block, &test.predicateMatchSpec, NewEmptyCustomContext())
			assert.Equal(t, test.expected, result, "`Or` match function evaluating incorrectly.")
		})
	}
}

func TestAndMatchFunction(t *testing.T) {
	var tests = []struct {
		name               string
		source             string
		predicateMatchSpec MatchSpec
		expected           bool
	}{
		{
			name: "check `and` match function with no true evaluation",
			source: `
resource "aws_ami" "example" {
}
`,
			predicateMatchSpec: testAndMatchSpec,
			expected:           false,
		},
		{
			name: "check `and` match function with a single true evaluation",
			source: `
resource "aws_ami" "example" {
	name = "placeholder-name"
}
`,
			predicateMatchSpec: testAndMatchSpec,
			expected:           false,
		},
		{
			name: "check `and` match function with all true evaluation",
			source: `
resource "aws_ami" "example" {
	name = "placeholder-name"
	description = "this is a description."
}
`,
			predicateMatchSpec: testAndMatchSpec,
			expected:           true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			block := parseFromSource(t, test.source)[0].GetBlocks()[0]
			result := evalMatchSpec(block, &test.predicateMatchSpec, NewEmptyCustomContext())
			assert.Equal(t, test.expected, result, "`And` match function evaluating incorrectly.")
		})
	}
}

func TestNestedMatchFunction(t *testing.T) {
	var tests = []struct {
		name               string
		source             string
		predicateMatchSpec MatchSpec
		expected           bool
	}{
		{
			name: "check nested match function with only inner true evaluation",
			source: `
resource "aws_ami" "example" {
	virtualization_type = "hvm"
	image_location = "image-XXXX"
	kernel_id = "XXXXXXXXXX"
}
`,
			predicateMatchSpec: testNestedMatchSpec,
			expected:           false,
		},
		{
			name: "check nested match function with no true evaluation",
			source: `
resource "aws_ami" "example" {
	virtualization_type = "hvm"
}
`,
			predicateMatchSpec: testNestedMatchSpec,
			expected:           false,
		},
		{
			name: "check nested match function with all true evaluation",
			source: `
resource "aws_ami" "example" {
	virtualization_type = "paravirtual"
	image_location = "image-XXXX"
	kernel_id = "XXXXXXXXXX"
}
`,
			predicateMatchSpec: testNestedMatchSpec,
			expected:           true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			block := parseFromSource(t, test.source)[0].GetBlocks()[0]
			result := evalMatchSpec(block, &test.predicateMatchSpec, NewEmptyCustomContext())
			assert.Equal(t, test.expected, result, "Nested match functions evaluating incorrectly.")
		})
	}
}

func TestNotFunction(t *testing.T) {
	var tests = []struct {
		name      string
		source    string
		matchSpec MatchSpec
		expected  bool
	}{
		{
			name: "check that not correctly inverts the outcome of a given predicateMatchSpec",
			source: `
resource "aws_ami" "example" {
	virtualization_type = "paravirtual"
}
`,
			matchSpec: testNotMatchSpec,
			expected:  false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			block := parseFromSource(t, test.source)[0].GetBlocks()[0]
			result := evalMatchSpec(block, &test.matchSpec, NewEmptyCustomContext())
			assert.Equal(t, test.expected, result, "Not match functions evaluating incorrectly.")
		})
	}
}

func TestPreCondition(t *testing.T) {
	var tests = []struct {
		name      string
		source    string
		matchSpec MatchSpec
		expected  bool
	}{
		{
			name: "check that precondition check prevents check being performed",
			source: `
resource "aws_ami" "testing" {
	name = "something else"
}
`,
			matchSpec: testPreConditionCheck,
			expected:  true,
		},
		{
			name: "check that precondition which passes allows check to be performed which fails",
			source: `
resource "aws_ami" "testing" {
	name = "something else"
	id   = "test-id"
}
`,
			matchSpec: testPreConditionCheck,
			expected:  false,
		},
		{
			name: "check that precondition which passes allows check to be performed which passes",
			source: `
resource "aws_ami" "testing" {
	name = "test-name"
	id   = "test-id"
}
`,
			matchSpec: testPreConditionCheck,
			expected:  true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			block := parseFromSource(t, test.source)[0].GetBlocks()[0]
			result := evalMatchSpec(block, &test.matchSpec, NewEmptyCustomContext())
			assert.Equal(t, test.expected, result, "precondition functions evaluating incorrectly.")
		})
	}
}

func TestAssignVariable(t *testing.T) {
	var tests = []struct {
		name      string
		source    string
		matchSpec MatchSpec
		expected  bool
	}{
		{
			name: "check assignVariable handling in pass case",
			source: `
resource "aws_s3_bucket" "test-bucket" {
  bucket = "test-bucket"

  lifecycle_rule {
    id = "test-bucket-rule-1"
  }
}
`,
			matchSpec: testAssignVariableMatchSpec,
			expected:  true,
		},
		{
			name: "check assignVariable handling in fail case",
			source: `
resource "aws_s3_bucket" "test-bucket" {
  bucket = "test-bucket"

  lifecycle_rule {
    id = "not-bucket-name-rule-1"
  }
}
`,
			matchSpec: testAssignVariableMatchSpec,
			expected:  false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			block := parseFromSource(t, test.source)[0].GetBlocks()[0]
			result := evalMatchSpec(block, &test.matchSpec, NewEmptyCustomContext())
			assert.Equal(t, test.expected, result, "processing variable assignments incorrectly.")
		})
	}
}

func TestRegexMatches(t *testing.T) {
	var tests = []struct {
		name               string
		source             string
		predicateMatchSpec MatchSpec
		expected           bool
	}{
		{
			name: "check `regexMatches` in pass case",
			source: `
resource "google_compute_instance" "default" {
  name         = "test_instance_name"
  machine_type = "e2-medium"
  region       = "europe-west3"
  zone         = "europe-west3-a"
}
`,
			predicateMatchSpec: MatchSpec{
				Name:       "name",
				Action:     "regexMatches",
				MatchValue: "^test_.*$",
			},
			expected: true,
		},
		{
			name: "check `regexMatches` in regex-not-matching fail case",
			source: `
resource "google_compute_instance" "default" {
  name         = "wrong_test_instance_name"
  machine_type = "e2-medium"
  region       = "europe-west3"
  zone         = "europe-west3-a"
}
`,
			predicateMatchSpec: MatchSpec{
				Name:       "name",
				Action:     "regexMatches",
				MatchValue: "^test_.*$",
			},
			expected: false,
		},
		{
			name: "check `regexMatches` in attribute-not-found fail case",
			source: `
resource "google_compute_instance" "default" {
  name         = "wrong_test_instance_name"
  machine_type = "e2-medium"
  region       = "europe-west3"
  zone         = "europe-west3-a"
}
`,
			predicateMatchSpec: MatchSpec{
				Name:       "not-name",
				Action:     "regexMatches",
				MatchValue: "^test_.*$",
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			block := parseFromSource(t, test.source)[0].GetBlocks()[0]
			result := evalMatchSpec(block, &test.predicateMatchSpec, NewEmptyCustomContext())
			assert.Equal(t, result, test.expected, "`regexMatches` match function evaluating incorrectly.")
		})
	}
}

func TestAttributeSubMatches(t *testing.T) {
	var tests = []struct {
		name      string
		source    string
		matchSpec MatchSpec
		expected  bool
	}{
		{
			name: "check that lack of subMatches should pass",
			source: `
resource "aws_instance" "foo" {
  tags = {
    Name = "tf-example"
  }
}
`,
			matchSpec: MatchSpec{
				Name:   "tags",
				Action: "isPresent",
			},
			expected: true,
		},
		{
			name: "check that a true `isPresent` map attribute subMatch should pass",
			source: `
resource "aws_instance" "foo" {
  tags = {
    Name = "tf-example"
  }
}
`,
			matchSpec: MatchSpec{
				Name:   "tags",
				Action: "isPresent",
				SubMatch: &MatchSpec{
					Name:   "Name",
					Action: "isPresent",
				},
			},
			expected: true,
		},
		{
			name: "check that a true `equals` map attribute subMatch should pass",
			source: `
resource "aws_instance" "foo" {
  tags = {
    Name = "tf-example"
  }
}
`,
			matchSpec: MatchSpec{
				Name:   "tags",
				Action: "isPresent",
				SubMatch: &MatchSpec{
					Name:       "Name",
					Action:     "equals",
					MatchValue: "tf-example",
				},
			},
			expected: true,
		},
		{
			name: "check that a false map attribute subMatch should fail",
			source: `
resource "aws_instance" "foo" {
  tags = {
    Name = "tf-example"
  }
}
`,
			matchSpec: MatchSpec{
				Name:   "tags",
				Action: "isPresent",
				SubMatch: &MatchSpec{
					Name:   "WrongName",
					Action: "isPresent",
				},
			},
			expected: false,
		},
		{
			name: "check that a not supported attribute subMatch should fail",
			source: `
resource "aws_instance" "foo" {
  tags = {
    Name = "tf-example"
  }
}
`,
			matchSpec: MatchSpec{
				Name:   "tags",
				Action: "isPresent",
				SubMatch: &MatchSpec{
					Name:   "Name",
					Action: "emptyAction",
				},
			},
			expected: false,
		},
		{
			name: "check that a truey numeric comparison in attribute subMatch should pass",
			source: `
resource "aws_instance" "foo" {
  tags = {
    InvalidButForTestingTag = 30
  }
}
`,
			matchSpec: MatchSpec{
				Name:   "tags",
				Action: "isPresent",
				SubMatch: &MatchSpec{
					Name:       "InvalidButForTestingTag",
					Action:     "lessThan",
					MatchValue: 10000,
				},
			},
			expected: true,
		},
		{
			name: "check that a fasley numeric comparison in attribute subMatch should fail",
			source: `
resource "aws_instance" "foo" {
  tags = {
    InvalidButForTestingTag = 30
  }
}
`,
			matchSpec: MatchSpec{
				Name:   "tags",
				Action: "isPresent",
				SubMatch: &MatchSpec{
					Name:       "InvalidButForTestingTag",
					Action:     "greaterThan",
					MatchValue: 10000,
				},
			},
			expected: false,
		},
		{
			name: "check that a truey `not` action in attribute subMatch should pass",
			source: `
resource "aws_instance" "foo" {
  tags = {
    Name = "Creator"
  }
}
`,
			matchSpec: MatchSpec{
				Name:   "tags",
				Action: "isPresent",
				SubMatch: &MatchSpec{
					Action: "not",
					PredicateMatchSpec: []MatchSpec{
						{
							Name:       "Name",
							Action:     "equals",
							MatchValue: "Blah",
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "check that a falsey `not` action in attribute subMatch should fail",
			source: `
resource "aws_instance" "foo" {
  tags = {
    Name = "Creator"
  }
}
`,
			matchSpec: MatchSpec{
				Name:   "tags",
				Action: "isPresent",
				SubMatch: &MatchSpec{
					Action: "not",
					PredicateMatchSpec: []MatchSpec{
						{
							Name:       "Name",
							Action:     "equals",
							MatchValue: "Creator",
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "check that a truey `and` action in attribute subMatch should pass",
			source: `
resource "aws_instance" "foo" {
  tags = {
    Name = "Creator"
  }
}
`,
			matchSpec: MatchSpec{
				Name:   "tags",
				Action: "isPresent",
				SubMatch: &MatchSpec{
					Action: "and",
					PredicateMatchSpec: []MatchSpec{
						{
							Name:       "Name",
							Action:     "equals",
							MatchValue: "Creator",
						},
						{
							Name:       "Name",
							Action:     "notEqual",
							MatchValue: "WrongValue",
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "check that a falsey `and` action in attribute subMatch should fail",
			source: `
resource "aws_instance" "foo" {
  tags = {
    Name = "Creator"
  }
}
`,
			matchSpec: MatchSpec{
				Name:   "tags",
				Action: "isPresent",
				SubMatch: &MatchSpec{
					Action: "and",
					PredicateMatchSpec: []MatchSpec{
						{
							Name:       "Name",
							Action:     "equals",
							MatchValue: "Creator",
						},
						{
							Name:       "Name",
							Action:     "equals",
							MatchValue: "WrongValue",
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "check that a false attribute subMatch with non-matching preconditions should pass",
			source: `
resource "aws_instance" "foo" {
  name = "just-a-name"
  tags = {
    Name = "tf-example"
  }
}
`,
			matchSpec: MatchSpec{
				Name:   "tags",
				Action: "isPresent",
				SubMatch: &MatchSpec{
					Name:       "Name",
					Action:     "equals",
					MatchValue: "wrong-value",
				},
				PreConditions: []MatchSpec{
					{
						Name:       "name",
						Action:     "equals",
						MatchValue: "another-name",
					},
				},
			},
			expected: true,
		},
		{
			name: "check that a false attribute subMatch with matching preconditions should fail",
			source: `
resource "aws_instance" "foo" {
  name = "just-a-name"
  tags = {
    Name = "tf-example"
  }
}
`,
			matchSpec: MatchSpec{
				Name:   "tags",
				Action: "isPresent",
				SubMatch: &MatchSpec{
					Name:       "Name",
					Action:     "equals",
					MatchValue: "wrong-value",
				},
				PreConditions: []MatchSpec{
					{
						Name:       "name",
						Action:     "equals",
						MatchValue: "just-a-name",
					},
				},
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			block := parseFromSource(t, test.source)[0].GetBlocks()[0]
			result := evalMatchSpec(block, &test.matchSpec, NewEmptyCustomContext())
			assert.Equal(t, result, test.expected, "subMatch evaluation function for attributes behaving incorrectly.")
		})
	}
}

func TestSubMatchOnes(t *testing.T) {
	var tests = []struct {
		name      string
		source    string
		matchSpec MatchSpec
		expected  bool
	}{
		{
			name:   "check `subMatchOne` in `subMatch`-only pass case",
			source: testSubMatchOnesSource,
			matchSpec: MatchSpec{
				Name:   "replica",
				Action: "isPresent",
				SubMatch: &MatchSpec{
					Name:   "region_name",
					Action: "isPresent",
				},
			},
			expected: true,
		},
		{
			name:   "check `subMatchOne` in `subMatch`-only fail case",
			source: testSubMatchOnesSource,
			matchSpec: MatchSpec{
				Name:   "replica",
				Action: "isPresent",
				SubMatch: &MatchSpec{
					Name:       "region_name",
					Action:     "equals",
					MatchValue: "us-east-2",
				},
			},
			expected: false,
		},
		{
			name:   "check `subMatchOne` in basic pass case",
			source: testSubMatchOnesSource,
			matchSpec: MatchSpec{
				Name:   "replica",
				Action: "isPresent",
				SubMatchOne: &MatchSpec{
					Name:       "region_name",
					Action:     "equals",
					MatchValue: "us-east-2",
				},
			},
			expected: true,
		},
		{
			name:   "check `subMatchOne` in multiple matches fail case",
			source: testSubMatchOnesSource,
			matchSpec: MatchSpec{
				Name:   "replica",
				Action: "isPresent",
				SubMatchOne: &MatchSpec{
					Name:       "region_name",
					Action:     "endsWith",
					MatchValue: "-2",
				},
			},
			expected: false,
		},
		{
			name:   "check `subMatchOne` in no match fail case",
			source: testSubMatchOnesSource,
			matchSpec: MatchSpec{
				Name:   "replica",
				Action: "isPresent",
				SubMatchOne: &MatchSpec{
					Name:       "region_name",
					Action:     "equals",
					MatchValue: "null-region",
				},
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			block := parseFromSource(t, test.source)[0].GetBlocks()[0]
			result := evalMatchSpec(block, &test.matchSpec, NewEmptyCustomContext())
			assert.Equal(t, result, test.expected, "`subMatchOne` handling function evaluating incorrectly.")
		})
	}
}

func givenCheck(jsonContent string) {
	var checksfile ChecksFile
	err := json.NewDecoder(strings.NewReader(jsonContent)).Decode(&checksfile)
	if err != nil {
		panic(err)
	}
	ProcessFoundChecks(checksfile)
}

func scanTerraform(t *testing.T, mainTf string) scan.Results {

	f := memoryfs.New()
	err := f.WriteFile("main.tf", []byte(mainTf), 0o600)
	require.NoError(t, err)

	results, err := scanner.New().ScanFS(context.TODO(), f, ".")
	require.NoError(t, err)
	return results
}

// This function is copied from setup_test.go as it is not possible to import function from test files.
func parseFromSource(t *testing.T, source string) terraform.Modules {
	f := createTestFile(t, "test.tf", source)
	p := parser.New(f, "", parser.OptionStopOnHCLError(true))
	err := p.ParseFS(context.TODO(), ".")
	require.NoError(t, err)
	modules, _, err := p.EvaluateAll(context.TODO())
	require.NoError(t, err)
	return modules
}

// This function is copied from setup_test.go as it is not possible to import function from test files.
func createTestFile(t *testing.T, filename, contents string) fs.FS {
	f := memoryfs.New()
	err := f.WriteFile(filename, []byte(contents), 0o600)
	require.NoError(t, err)
	return f
}
