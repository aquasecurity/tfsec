package test

import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/parser"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/pkg/provider"
	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/rule"
	"github.com/aquasecurity/tfsec/pkg/severity"
)

var badRule = rule.Rule{
	LegacyID:  "EXA001",
	Provider:  provider.AWSProvider,
	Service:   "service",
	ShortCode: "abc",
	Documentation: rule.RuleDocumentation{
		Summary:     "A stupid example check for a test.",
		Impact:      "You will look stupid",
		Resolution:  "Don't do stupid stuff",
		Explanation: "Bad should not be set.",
		BadExample: []string{`
resource "problem" "x" {
bad = "1"
}
`},
		GoodExample: []string{`
resource "problem" "x" {

}
`},
		Links: nil,
	},
	RequiredTypes:   []string{"resource"},
	RequiredLabels:  []string{"problem"},
	DefaultSeverity: severity.High,
	CheckFunc: func(set result.Set, resourceBlock block.Block, _ block.Module) {
		if resourceBlock.GetAttribute("bad").IsTrue() {
			set.AddResult().
				WithDescription("example problem")
		}
	},
}

func Test_ProblemInModuleInSiblingDir(t *testing.T) {

	scanner.RegisterCheckRule(badRule)
	defer scanner.DeregisterCheckRule(badRule)

	fs, err := testutil.NewFilesystem()
	require.NoError(t, err)
	defer fs.Close()

	require.NoError(t, fs.WriteTextFile("/project/main.tf", `
module "something" {
	source = "../modules/problem"
}
`))
	require.NoError(t, fs.WriteTextFile("modules/problem/main.tf", `
resource "problem" "uhoh" {
	bad = true
}
`))

	blocks, err := parser.New(fs.RealPath("/project/"), parser.OptionStopOnHCLError()).ParseDirectory()
	require.NoError(t, err)
	results := scanner.New().Scan(blocks)
	testutil.AssertCheckCode(t, badRule.ID(), "", results)

}

func Test_ProblemInModuleInSubdirectory(t *testing.T) {

	scanner.RegisterCheckRule(badRule)
	defer scanner.DeregisterCheckRule(badRule)

	fs, err := testutil.NewFilesystem()
	require.NoError(t, err)
	defer fs.Close()

	require.NoError(t, fs.WriteTextFile("project/main.tf", `
module "something" {
	source = "./modules/problem"
}
`))
	require.NoError(t, fs.WriteTextFile("project/modules/problem/main.tf", `
resource "problem" "uhoh" {
	bad = true
}
`))

	blocks, err := parser.New(fs.RealPath("project/"), parser.OptionStopOnHCLError()).ParseDirectory()
	require.NoError(t, err)
	results := scanner.New().Scan(blocks)
	testutil.AssertCheckCode(t, badRule.ID(), "", results)

}

func Test_ProblemInModuleInParentDir(t *testing.T) {

	scanner.RegisterCheckRule(badRule)
	defer scanner.DeregisterCheckRule(badRule)

	fs, err := testutil.NewFilesystem()
	require.NoError(t, err)
	defer fs.Close()

	require.NoError(t, fs.WriteTextFile("project/main.tf", `
module "something" {
	source = "../problem"
}
`))
	require.NoError(t, fs.WriteTextFile("problem/main.tf", `
resource "problem" "uhoh" {
	bad = true
}
`))

	blocks, err := parser.New(fs.RealPath("project/"), parser.OptionStopOnHCLError()).ParseDirectory()
	require.NoError(t, err)
	results := scanner.New().Scan(blocks)
	testutil.AssertCheckCode(t, badRule.ID(), "", results)

}

func Test_ProblemInModuleReuse(t *testing.T) {

	scanner.RegisterCheckRule(badRule)
	defer scanner.DeregisterCheckRule(badRule)

	fs, err := testutil.NewFilesystem()
	require.NoError(t, err)
	defer fs.Close()

	require.NoError(t, fs.WriteTextFile("project/main.tf", `
module "something_good" {
	source = "../modules/problem"
	bad = false
}

module "something_bad" {
	source = "../modules/problem"
	bad = true
}
`))
	require.NoError(t, fs.WriteTextFile("modules/problem/main.tf", `
variable "bad" {
	default = false
}
resource "problem" "uhoh" {
	bad = var.bad
}
`))

	blocks, err := parser.New(fs.RealPath("project/"), parser.OptionStopOnHCLError()).ParseDirectory()
	require.NoError(t, err)
	results := scanner.New().Scan(blocks)
	testutil.AssertCheckCode(t, badRule.ID(), "", results)

}

func Test_ProblemInNestedModule(t *testing.T) {

	scanner.RegisterCheckRule(badRule)
	defer scanner.DeregisterCheckRule(badRule)

	fs, err := testutil.NewFilesystem()
	require.NoError(t, err)
	defer fs.Close()

	require.NoError(t, fs.WriteTextFile("project/main.tf", `
module "something" {
	source = "../modules/a"
}
`))
	require.NoError(t, fs.WriteTextFile("modules/a/main.tf", `
	module "something" {
	source = "../../modules/b"
}
`))
	require.NoError(t, fs.WriteTextFile("modules/b/main.tf", `
module "something" {
	source = "../c"
}
`))
	require.NoError(t, fs.WriteTextFile("modules/c/main.tf", `
resource "problem" "uhoh" {
	bad = true
}
`))

	blocks, err := parser.New(fs.RealPath("project/"), parser.OptionStopOnHCLError()).ParseDirectory()
	require.NoError(t, err)
	results := scanner.New().Scan(blocks)
	testutil.AssertCheckCode(t, badRule.ID(), "", results)

}

func Test_ProblemInReusedNestedModule(t *testing.T) {

	scanner.RegisterCheckRule(badRule)
	defer scanner.DeregisterCheckRule(badRule)

	fs, err := testutil.NewFilesystem()
	require.NoError(t, err)
	defer fs.Close()

	require.NoError(t, fs.WriteTextFile("project/main.tf", `
module "something" {
  source = "../modules/a"
  bad = false
}

module "something-bad" {
	source = "../modules/a"
	bad = true
}
`))
	require.NoError(t, fs.WriteTextFile("modules/a/main.tf", `
variable "bad" {
	default = false
}
module "something" {
	source = "../../modules/b"
	bad = var.bad
}
`))
	require.NoError(t, fs.WriteTextFile("modules/b/main.tf", `
variable "bad" {
	default = false
}
module "something" {
	source = "../c"
	bad = var.bad
}
`))
	require.NoError(t, fs.WriteTextFile("modules/c/main.tf", `
variable "bad" {
	default = false
}
resource "problem" "uhoh" {
	bad = var.bad
}
`))

	blocks, err := parser.New(fs.RealPath("project/"), parser.OptionStopOnHCLError()).ParseDirectory()
	require.NoError(t, err)
	results := scanner.New().Scan(blocks)
	testutil.AssertCheckCode(t, badRule.ID(), "", results)

}

func Test_ProblemInInitialisedModule(t *testing.T) {

	scanner.RegisterCheckRule(badRule)
	defer scanner.DeregisterCheckRule(badRule)

	fs, err := testutil.NewFilesystem()
	require.NoError(t, err)
	defer fs.Close()

	require.NoError(t, fs.WriteTextFile("project/main.tf", `
module "something" {
  	source = "/nowhere"
	bad = true
}
`))
	require.NoError(t, fs.WriteTextFile("project/.terraform/modules/a/main.tf", `
variable "bad" {
	default = false
}
resource "problem" "uhoh" {
	bad = var.bad
}
`))
	require.NoError(t, fs.WriteTextFile("project/.terraform/modules/modules.json", `
	{"Modules":[{"Key":"something","Source":"/nowhere","Version":"2.35.0","Dir":".terraform/modules/a"}]}
`))

	blocks, err := parser.New(fs.RealPath("project/"), parser.OptionStopOnHCLError()).ParseDirectory()
	require.NoError(t, err)
	results := scanner.New().Scan(blocks)
	testutil.AssertCheckCode(t, badRule.ID(), "", results)

}
func Test_ProblemInReusedInitialisedModule(t *testing.T) {

	scanner.RegisterCheckRule(badRule)
	defer scanner.DeregisterCheckRule(badRule)

	fs, err := testutil.NewFilesystem()
	require.NoError(t, err)
	defer fs.Close()

	require.NoError(t, fs.WriteTextFile("project/main.tf", `
module "something" {
  	source = "/nowhere"
	bad = false
} 
module "something2" {
	source = "/nowhere"
  	bad = true
}
`))
	require.NoError(t, fs.WriteTextFile("project/.terraform/modules/a/main.tf", `
variable "bad" {
	default = false
}
resource "problem" "uhoh" {
	bad = var.bad
}
`))
	require.NoError(t, fs.WriteTextFile("project/.terraform/modules/modules.json", `
	{"Modules":[{"Key":"something","Source":"/nowhere","Version":"2.35.0","Dir":".terraform/modules/a"}]}
`))

	blocks, err := parser.New(fs.RealPath("project/"), parser.OptionStopOnHCLError()).ParseDirectory()
	require.NoError(t, err)
	results := scanner.New().Scan(blocks)
	testutil.AssertCheckCode(t, badRule.ID(), "", results)

}

func Test_ProblemInDuplicateModuleNameAndPath(t *testing.T) {
	scanner.RegisterCheckRule(badRule)
	defer scanner.DeregisterCheckRule(badRule)

	fs, err := testutil.NewFilesystem()
	require.NoError(t, err)
	defer fs.Close()

	require.NoError(t, fs.WriteTextFile("project/main.tf", `
module "something" {
  source = "../modules/a"
  bad = 0
}

module "something-bad" {
	source = "../modules/a"
	bad = 1
}
`))
	require.NoError(t, fs.WriteTextFile("modules/a/main.tf", `
variable "bad" {
	default = 0
}
module "something" {
	source = "../b"
	bad = var.bad
}
`))
	require.NoError(t, fs.WriteTextFile("modules/b/main.tf", `
variable "bad" {
	default = 0
}
module "something" {
	source = "../c"
	bad = var.bad
}
`))
	require.NoError(t, fs.WriteTextFile("modules/c/main.tf", `
variable "bad" {
	default = 0
}
resource "problem" "uhoh" {
	count = var.bad
	bad = true
}
`))

	blocks, err := parser.New(fs.RealPath("project/"), parser.OptionStopOnHCLError()).ParseDirectory()
	require.NoError(t, err)
	results := scanner.New().Scan(blocks)
	testutil.AssertCheckCode(t, badRule.ID(), "", results)

}

func Test_UniqueDataBlocksWhenRaceInLoad(t *testing.T) {
	fs, err := testutil.NewFilesystem()
	require.NoError(t, err)
	defer fs.Close()

	require.NoError(t, fs.WriteTextFile("project/main.tf", `
module "something" {
  	source = "../modules/iam"
} 
`))
	require.NoError(t, fs.WriteTextFile("/modules/iam/main2.tf", `
	resource "aws_iam_role_policy" "test_policy" {
		name = "test_policy"
		role = aws_iam_role.test_role.id
	
		policy = data.aws_iam_policy_document.s3_policy.json
	}
	
	resource "aws_iam_role" "test_role" {
		name = "test_role"
		assume_role_policy = jsonencode({
			Version = "2012-10-17"
			Statement = [
			{
				Action = "sts:AssumeRole"
				Effect = "Allow"
				Sid    = ""
				Principal = {
				Service = "s3.amazonaws.com"
				}
			},
			]
		})
	}
	
	data "aws_iam_policy_document" "s3_policy" {
	  statement {
		principals {
		  type        = "AWS"
		  identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
		}
		actions   = ["s3:*"]
		resources = ["*"]
	  }
	}
`))
	require.NoError(t, fs.WriteTextFile("/modules/iam/main1.tf", `
	resource "aws_iam_role_policy" "test_policy2" {
		name = "test_policy"
		role = aws_iam_role.test_role.id
	
		policy = data.aws_iam_policy_document.s3_policy.json
	}
	
	resource "aws_iam_role" "test_role2" {
		name = "test_role"
		assume_role_policy = jsonencode({
			Version = "2012-10-17"
			Statement = [
			{
				Action = "sts:AssumeRole"
				Effect = "Allow"
				Sid    = ""
				Principal = {
				Service = "s3.amazonaws.com"
				}
			},
			]
		})
	}
	
	data "aws_iam_policy_document" "s3_policy2" {
	  statement {
		principals {
		  type        = "AWS"
		  identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
		}
		actions   = ["s3:nope"]
		resources = ["nopeSSS"]
	  }
	}
`))

	blocks, err := parser.New(fs.RealPath("project/"), parser.OptionStopOnHCLError()).ParseDirectory()
	require.NoError(t, err)
	results := scanner.New().Scan(blocks)
	testutil.AssertCheckCode(t, "aws-iam-no-policy-wildcards", "", results)
}

func Test_Dynamic_Variables(t *testing.T) {
	example := `
resource "something" "this" {

	dynamic "blah" {
		for_each = ["a"]

		content {
			policy = "TLS_1_0"
		}
	}
}
	
resource "aws_api_gateway_domain_name" "outdated_security_policy" {
	security_policy = something.this.blah.policy
}
`
	fs, err := testutil.NewFilesystem()
	require.NoError(t, err)
	defer fs.Close()

	require.NoError(t, fs.WriteTextFile("project/main.tf", example))
	blocks, err := parser.New(fs.RealPath("project/"), parser.OptionStopOnHCLError()).ParseDirectory()
	require.NoError(t, err)
	results := scanner.New().Scan(blocks)
	testutil.AssertCheckCode(t, "aws-api-gateway-use-secure-tls-policy", "", results)
}

func Test_Dynamic_Variables_FalsePositive(t *testing.T) {
	example := `
resource "aws_s3_bucket" "bucket" {
	x = 1
	dynamic "blah" {
		for_each = ["TLS_1_2"]

		content {
			policy = each.value
		}
	}
}
	
resource "aws_api_gateway_domain_name" "outdated_security_policy" {
	security_policy = aws_s3_bucket.bucket.blah.policy
}
`
	fs, err := testutil.NewFilesystem()
	require.NoError(t, err)
	defer fs.Close()

	require.NoError(t, fs.WriteTextFile("project/main.tf", example))
	blocks, err := parser.New(fs.RealPath("project/"), parser.OptionStopOnHCLError()).ParseDirectory()
	require.NoError(t, err)
	results := scanner.New().Scan(blocks)
	testutil.AssertCheckCode(t, "", "aws-api-gateway-use-secure-tls-policy", results)
}
