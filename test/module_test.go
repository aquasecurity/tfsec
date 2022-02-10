package test

import (
    "testing"

    "github.com/aquasecurity/tfsec/internal/pkg/testutil"
    "github.com/aquasecurity/tfsec/internal/pkg/testutil/filesystem"
    "github.com/stretchr/testify/require"

    "github.com/aquasecurity/defsec/provider"
    "github.com/aquasecurity/defsec/rules"
    "github.com/aquasecurity/defsec/rules/aws/iam"
    "github.com/aquasecurity/defsec/severity"
    "github.com/aquasecurity/tfsec/internal/pkg/scanner"
    "github.com/aquasecurity/tfsec/pkg/rule"
    "github.com/aquasecurity/trivy-config-parsers/terraform"
    "github.com/aquasecurity/trivy-config-parsers/terraform/parser"
)

var badRule = rule.Rule{
    Base: rules.Register(rules.Rule{
        Provider:    provider.AWSProvider,
        Service:     "service",
        ShortCode:   "abc",
        Summary:     "A stupid example check for a test.",
        Impact:      "You will look stupid",
        Resolution:  "Don't do stupid stuff",
        Explanation: "Bad should not be set.",
        Severity:    severity.High,
    }, nil),
    RequiredTypes:  []string{"resource"},
    RequiredLabels: []string{"problem"},
    CheckTerraform: func(resourceBlock *terraform.Block, _ *terraform.Module) (results rules.Results) {
        if attr := resourceBlock.GetAttribute("bad"); attr.IsTrue() {
            results.Add("bad", attr)
        }
        return
    },
}

// IMPORTANT: if this test is failing, you probably need to set the version of go-cty in go.mod to the same version that hcl uses.
func Test_GoCtyCompatibilityIssue(t *testing.T) {
    scanner.RegisterCheckRule(badRule)
    defer scanner.DeregisterCheckRule(badRule)

    fs, err := filesystem.New()
    require.NoError(t, err)
    defer fs.Close()

    require.NoError(t, fs.WriteTextFile("/project/main.tf", `
data "aws_vpc" "default" {
  default = true
}

module "test" {
  source     = "../modules/problem/"
  cidr_block = data.aws_vpc.default.cidr_block
}
`))
    require.NoError(t, fs.WriteTextFile("/modules/problem/main.tf", `
variable "cidr_block" {}

variable "open" {                
  default = false
}                

resource "aws_security_group" "this" {
  name = "Test"                       

  ingress {    
    description = "HTTPs"
    from_port   = 443    
    to_port     = 443
    protocol    = "tcp"
    self        = ! var.open
    cidr_blocks = var.open ? [var.cidr_block] : null
  }                                                 
}  

resource "problem" "uhoh" {
	bad = true
}
`))

    p := parser.New(parser.OptionStopOnHCLError())
    err = p.ParseDirectory(fs.RealPath("project/"))
    require.NoError(t, err)
    modules, _, err := p.EvaluateAll()
    require.NoError(t, err)
    results, _ := scanner.New().Scan(modules)
    testutil.AssertRuleFound(t, badRule.ID(), results, "")

}

func Test_ProblemInModuleInSiblingDir(t *testing.T) {

    scanner.RegisterCheckRule(badRule)
    defer scanner.DeregisterCheckRule(badRule)

    fs, err := filesystem.New()
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

    p := parser.New(parser.OptionStopOnHCLError())
    err = p.ParseDirectory(fs.RealPath("project/"))
    require.NoError(t, err)
    modules, _, err := p.EvaluateAll()
    require.NoError(t, err)
    results, _ := scanner.New().Scan(modules)
    testutil.AssertRuleFound(t, badRule.ID(), results, "")

}

func Test_ProblemInModuleIgnored(t *testing.T) {

    scanner.RegisterCheckRule(badRule)
    defer scanner.DeregisterCheckRule(badRule)

    fs, err := filesystem.New()
    require.NoError(t, err)
    defer fs.Close()

    require.NoError(t, fs.WriteTextFile("/project/main.tf", `
#tfsec:ignore:aws-service-abc
module "something" {
	source = "../modules/problem"
}
`))
    require.NoError(t, fs.WriteTextFile("modules/problem/main.tf", `
resource "problem" "uhoh" {
	bad = true
}
`))

    p := parser.New(parser.OptionStopOnHCLError())
    err = p.ParseDirectory(fs.RealPath("project/"))
    require.NoError(t, err)
    modules, _, err := p.EvaluateAll()
    require.NoError(t, err)
    results, _ := scanner.New().Scan(modules)
    testutil.AssertRuleNotFound(t, badRule.ID(), results, "")

}

func Test_ProblemInModuleInSubdirectory(t *testing.T) {

    scanner.RegisterCheckRule(badRule)
    defer scanner.DeregisterCheckRule(badRule)

    fs, err := filesystem.New()
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

    p := parser.New(parser.OptionStopOnHCLError())
    err = p.ParseDirectory(fs.RealPath("project/"))
    require.NoError(t, err)
    modules, _, err := p.EvaluateAll()
    require.NoError(t, err)
    results, _ := scanner.New().Scan(modules)
    testutil.AssertRuleFound(t, badRule.ID(), results, "")

}

func Test_ProblemInModuleInParentDir(t *testing.T) {

    scanner.RegisterCheckRule(badRule)
    defer scanner.DeregisterCheckRule(badRule)

    fs, err := filesystem.New()
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

    p := parser.New(parser.OptionStopOnHCLError())
    err = p.ParseDirectory(fs.RealPath("project/"))
    require.NoError(t, err)
    modules, _, err := p.EvaluateAll()
    require.NoError(t, err)
    results, _ := scanner.New().Scan(modules)
    testutil.AssertRuleFound(t, badRule.ID(), results, "")

}

func Test_ProblemInModuleReuse(t *testing.T) {

    scanner.RegisterCheckRule(badRule)
    defer scanner.DeregisterCheckRule(badRule)

    fs, err := filesystem.New()
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

    p := parser.New(parser.OptionStopOnHCLError())
    err = p.ParseDirectory(fs.RealPath("project/"))
    require.NoError(t, err)
    modules, _, err := p.EvaluateAll()
    require.NoError(t, err)
    results, _ := scanner.New().Scan(modules)
    testutil.AssertRuleFound(t, badRule.ID(), results, "")

}

func Test_ProblemInNestedModule(t *testing.T) {

    scanner.RegisterCheckRule(badRule)
    defer scanner.DeregisterCheckRule(badRule)

    fs, err := filesystem.New()
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

    p := parser.New(parser.OptionStopOnHCLError())
    err = p.ParseDirectory(fs.RealPath("project/"))
    require.NoError(t, err)
    modules, _, err := p.EvaluateAll()
    require.NoError(t, err)
    results, _ := scanner.New().Scan(modules)
    testutil.AssertRuleFound(t, badRule.ID(), results, "")

}

func Test_ProblemInReusedNestedModule(t *testing.T) {

    scanner.RegisterCheckRule(badRule)
    defer scanner.DeregisterCheckRule(badRule)

    fs, err := filesystem.New()
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

    p := parser.New(parser.OptionStopOnHCLError())
    err = p.ParseDirectory(fs.RealPath("project/"))
    require.NoError(t, err)
    modules, _, err := p.EvaluateAll()
    require.NoError(t, err)
    results, _ := scanner.New().Scan(modules)
    testutil.AssertRuleFound(t, badRule.ID(), results, "")

}

func Test_ProblemInInitialisedModule(t *testing.T) {

    scanner.RegisterCheckRule(badRule)
    defer scanner.DeregisterCheckRule(badRule)

    fs, err := filesystem.New()
    require.NoError(t, err)
    defer fs.Close()

    require.NoError(t, fs.WriteTextFile("project/main.tf", `
module "something" {
  	source = "../modules/somewhere"
	bad = false
}
`))
    require.NoError(t, fs.WriteTextFile("modules/somewhere/main.tf", `
module "something_nested" {
	count = 1
  	source = "github.com/some/module.git"
	bad = true
}

variable "bad" {
	default = false
}

`))
    require.NoError(t, fs.WriteTextFile("project/.terraform/modules/something.something_nested/main.tf", `
variable "bad" {
	default = false
}
resource "problem" "uhoh" {
	bad = var.bad
}
`))
    require.NoError(t, fs.WriteTextFile("project/.terraform/modules/modules.json", `
	{"Modules":[
        {"Key":"something","Source":"../modules/somewhere","Version":"2.35.0","Dir":"../modules/somewhere"},
        {"Key":"something.something_nested","Source":"git::https://github.com/some/module.git","Version":"2.35.0","Dir":".terraform/modules/something.something_nested"}
    ]}
`))

    p := parser.New(parser.OptionStopOnHCLError())
    err = p.ParseDirectory(fs.RealPath("project/"))
    require.NoError(t, err)
    modules, _, err := p.EvaluateAll()
    require.NoError(t, err)
    results, _ := scanner.New().Scan(modules)
    testutil.AssertRuleFound(t, badRule.ID(), results, "")

}
func Test_ProblemInReusedInitialisedModule(t *testing.T) {

    scanner.RegisterCheckRule(badRule)
    defer scanner.DeregisterCheckRule(badRule)

    fs, err := filesystem.New()
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
	{"Modules":[{"Key":"something","Source":"/nowhere","Version":"2.35.0","Dir":".terraform/modules/a"},{"Key":"something2","Source":"/nowhere","Version":"2.35.0","Dir":".terraform/modules/a"}]}
`))

    p := parser.New(parser.OptionStopOnHCLError())
    err = p.ParseDirectory(fs.RealPath("project/"))
    require.NoError(t, err)
    modules, _, err := p.EvaluateAll()
    require.NoError(t, err)
    results, _ := scanner.New().Scan(modules)
    testutil.AssertRuleFound(t, badRule.ID(), results, "")

}

func Test_ProblemInDuplicateModuleNameAndPath(t *testing.T) {
    scanner.RegisterCheckRule(badRule)
    defer scanner.DeregisterCheckRule(badRule)

    fs, err := filesystem.New()
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

    p := parser.New(parser.OptionStopOnHCLError())
    err = p.ParseDirectory(fs.RealPath("project/"))
    require.NoError(t, err)
    modules, _, err := p.EvaluateAll()
    require.NoError(t, err)
    results, _ := scanner.New().Scan(modules)
    testutil.AssertRuleFound(t, badRule.ID(), results, "")

}

func Test_Dynamic_Variables(t *testing.T) {
    example := `
resource "something" "this" {

	dynamic "blah" {
		for_each = ["a"]

		content {
			ok = true
		}
	}
}
	
resource "bad" "thing" {
	secure = something.this.blah.ok
}
`
    fs, err := filesystem.New()
    require.NoError(t, err)
    defer fs.Close()

    require.NoError(t, fs.WriteTextFile("project/main.tf", example))

    r1 := rule.Rule{
        Base: rules.Register(rules.Rule{
            Provider:  provider.AWSProvider,
            Service:   "service",
            ShortCode: "abc123",
            Severity:  severity.High,
        }, nil),
        RequiredLabels: []string{"bad"},
        CheckTerraform: func(resourceBlock *terraform.Block, _ *terraform.Module) (results rules.Results) {
            if resourceBlock.GetAttribute("secure").IsTrue() {
                return
            }
            results.Add("example problem", resourceBlock)
            return
        },
    }
    scanner.RegisterCheckRule(r1)
    defer scanner.DeregisterCheckRule(r1)

    p := parser.New(parser.OptionStopOnHCLError())
    err = p.ParseDirectory(fs.RealPath("project/"))
    require.NoError(t, err)
    modules, _, err := p.EvaluateAll()
    require.NoError(t, err)
    results, _ := scanner.New().Scan(modules)
    testutil.AssertRuleFound(t, r1.ID(), results, "")
}

func Test_Dynamic_Variables_FalsePositive(t *testing.T) {
    example := `
resource "something" "else" {
	x = 1
	dynamic "blah" {
		for_each = [true]

		content {
			ok = each.value
		}
	}
}
	
resource "bad" "thing" {
	secure = something.else.blah.ok
}
`
    fs, err := filesystem.New()
    require.NoError(t, err)
    defer fs.Close()

    require.NoError(t, fs.WriteTextFile("project/main.tf", example))

    r1 := rule.Rule{
        Base: rules.Register(rules.Rule{
            Provider:  provider.AWSProvider,
            Service:   "service",
            ShortCode: "abc123",
            Severity:  severity.High,
        }, nil),
        RequiredLabels: []string{"bad"},
        CheckTerraform: func(resourceBlock *terraform.Block, _ *terraform.Module) (results rules.Results) {
            if resourceBlock.GetAttribute("secure").IsTrue() {
                return
            }
            results.Add("example problem", resourceBlock)
            return
        },
    }
    scanner.RegisterCheckRule(r1)
    defer scanner.DeregisterCheckRule(r1)

    p := parser.New(parser.OptionStopOnHCLError())
    err = p.ParseDirectory(fs.RealPath("project/"))
    require.NoError(t, err)
    modules, _, err := p.EvaluateAll()
    require.NoError(t, err)
    results, _ := scanner.New().Scan(modules)
    testutil.AssertRuleNotFound(t, r1.ID(), results, "")
}

func Test_ReferencesPassedToNestedModule(t *testing.T) {

    r := rule.Rule{
        Base: iam.CheckEnforceMFA,
    }

    scanner.RegisterCheckRule(r)
    defer scanner.DeregisterCheckRule(r)

    fs, err := filesystem.New()
    require.NoError(t, err)
    defer fs.Close()

    require.NoError(t, fs.WriteTextFile("project/main.tf", `

resource "aws_iam_group" "developers" {
    name = "developers"
}

module "something" {
	source = "../modules/a"
    group = aws_iam_group.developers.name
}
`))
    require.NoError(t, fs.WriteTextFile("modules/a/main.tf", `

variable "group" {
    type = "string"
}

resource aws_iam_group_policy mfa {
  group = var.group
  policy = data.aws_iam_policy_document.policy.json
}

data "aws_iam_policy_document" "policy" {
  statement {
    sid    = "main"
    effect = "Allow"

    actions   = ["s3:*"]
    resources = ["*"]
    condition {
        test = "Bool"
        variable = "aws:MultiFactorAuthPresent"
        values = ["true"]
    }
  }
}

`))
    p := parser.New(parser.OptionStopOnHCLError())
    err = p.ParseDirectory(fs.RealPath("project/"))
    require.NoError(t, err)
    modules, _, err := p.EvaluateAll()
    require.NoError(t, err)
    results, _ := scanner.New().Scan(modules)
    testutil.AssertRuleNotFound(t, r.ID(), results, "")

}
