package test

import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/pkg/testutil/filesystem"

	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"

	"github.com/aquasecurity/tfsec/internal/pkg/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/tfsec/internal/pkg/scanner"
	"github.com/aquasecurity/tfsec/pkg/rule"
	"github.com/aquasecurity/trivy-config-parsers/terraform"
	"github.com/aquasecurity/trivy-config-parsers/terraform/parser"
)

var panicRule = rule.Rule{
	Base: rules.Register(
		rules.Rule{
			Provider:  provider.AWSProvider,
			Service:   "service",
			ShortCode: "abc",
			Severity:  severity.High,
		},
		nil,
	),
	RequiredTypes:  []string{"resource"},
	RequiredLabels: []string{"problem"},
	CheckTerraform: func(resourceBlock *terraform.Block, _ *terraform.Module) (results rules.Results) {
		if resourceBlock.GetAttribute("panic").IsTrue() {
			panic("This is fine")
		}
		return
	},
}

func Test_PanicInCheckNotAllowed(t *testing.T) {

	scanner.RegisterCheckRule(panicRule)
	defer scanner.DeregisterCheckRule(panicRule)

	fs, err := filesystem.New()
	require.NoError(t, err)
	defer fs.Close()

	require.NoError(t, fs.WriteTextFile("project/main.tf", `
resource "problem" "this" {
	panic = true
}
`))
	p := parser.New(parser.OptionStopOnHCLError())
	err = p.ParseDirectory(fs.RealPath("/project"))
	require.NoError(t, err)
	modules, _, err := p.EvaluateAll()
	require.NoError(t, err)
	results, _ := scanner.New().Scan(modules)
	testutil.AssertRuleNotFound(t, panicRule.ID(), results, "")
}

func Test_PanicInCheckAllowed(t *testing.T) {

	scanner.RegisterCheckRule(panicRule)
	defer scanner.DeregisterCheckRule(panicRule)

	fs, err := filesystem.New()
	require.NoError(t, err)
	defer fs.Close()

	require.NoError(t, fs.WriteTextFile("project/main.tf", `
resource "problem" "this" {
	panic = true
}
`))

	p := parser.New(parser.OptionStopOnHCLError())
	err = p.ParseDirectory(fs.RealPath("/project"))
	require.NoError(t, err)
	modules, _, err := p.EvaluateAll()
	require.NoError(t, err)
	_, err = scanner.New(scanner.OptionStopOnErrors()).Scan(modules)
	assert.Error(t, err)
}

func Test_PanicNotInCheckNotIncludePassed(t *testing.T) {

	scanner.RegisterCheckRule(panicRule)
	defer scanner.DeregisterCheckRule(panicRule)

	fs, err := filesystem.New()
	require.NoError(t, err)
	defer fs.Close()

	require.NoError(t, fs.WriteTextFile("project/main.tf", `
resource "problem" "this" {
	panic = true
}
`))

	p := parser.New(parser.OptionStopOnHCLError())
	err = p.ParseDirectory(fs.RealPath("/project"))
	require.NoError(t, err)
	modules, _, err := p.EvaluateAll()
	require.NoError(t, err)
	results, _ := scanner.New().Scan(modules)
	testutil.AssertRuleNotFound(t, panicRule.ID(), results, "")
}

func Test_PanicNotInCheckNotIncludePassedStopOnError(t *testing.T) {

	scanner.RegisterCheckRule(panicRule)
	defer scanner.DeregisterCheckRule(panicRule)

	fs, err := filesystem.New()
	require.NoError(t, err)
	defer fs.Close()

	require.NoError(t, fs.WriteTextFile("project/main.tf", `
resource "problem" "this" {
	panic = true
}
`))

	p := parser.New(parser.OptionStopOnHCLError())
	err = p.ParseDirectory(fs.RealPath("/project"))
	require.NoError(t, err)
	modules, _, err := p.EvaluateAll()
	require.NoError(t, err)

	_, err = scanner.New(scanner.OptionStopOnErrors()).Scan(modules)
	assert.Error(t, err)
}
