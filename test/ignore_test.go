package test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/aquasecurity/tfsec/internal/pkg/legacy"
	"github.com/aquasecurity/tfsec/internal/pkg/testutil"

	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"

	"github.com/aquasecurity/trivy-config-parsers/terraform"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tfsec/internal/pkg/scanner"

	"github.com/stretchr/testify/assert"
)

var exampleRule = rule.Rule{
	Base: rules.Register(rules.Rule{
		Provider:  provider.AWSProvider,
		Service:   "service",
		ShortCode: "abc123",
		Severity:  severity.High,
	}, nil),
	RequiredLabels: []string{"bad"},
	CheckTerraform: func(resourceBlock *terraform.Block, _ *terraform.Module) (results rules.Results) {
		attr := resourceBlock.GetAttribute("secure")
		if attr.IsNil() {
			results.Add("example problem", resourceBlock)
		}
		if attr.IsFalse() {
			results.Add("example problem", attr)
		}
		return
	},
}

func Test_IgnoreAll(t *testing.T) {
	scanner.RegisterCheckRule(exampleRule)
	defer scanner.DeregisterCheckRule(exampleRule)

	results := testutil.ScanHCL(`
resource "bad" "my-rule" {
    secure = false // tfsec:ignore:*
}
`, t)
	assert.Len(t, results, 0)

}

func Test_IgnoreLineAboveTheBlock(t *testing.T) {
	scanner.RegisterCheckRule(exampleRule)
	defer scanner.DeregisterCheckRule(exampleRule)

	results := testutil.ScanHCL(`
// tfsec:ignore:*
resource "bad" "my-rule" {
   secure = false 
}
`, t)
	assert.Len(t, results, 0)
}

func Test_IgnoreLineAboveTheBlockMatchingParamBool(t *testing.T) {
	scanner.RegisterCheckRule(exampleRule)
	defer scanner.DeregisterCheckRule(exampleRule)

	results := testutil.ScanHCL(`
// tfsec:ignore:*[secure=false]
resource "bad" "my-rule" {
   secure = false
}
`, t)
	assert.Len(t, results, 0)
}

func Test_IgnoreLineAboveTheBlockNotMatchingParamBool(t *testing.T) {
	scanner.RegisterCheckRule(exampleRule)
	defer scanner.DeregisterCheckRule(exampleRule)

	results := testutil.ScanHCL(`
// tfsec:ignore:*[secure=true]
resource "bad" "my-rule" {
   secure = false 
}
`, t)
	assert.Len(t, results, 1)
}

func Test_IgnoreLineAboveTheBlockMatchingParamString(t *testing.T) {
	scanner.RegisterCheckRule(exampleRule)
	defer scanner.DeregisterCheckRule(exampleRule)

	results := testutil.ScanHCL(`
// tfsec:ignore:*[name=myrule]
resource "bad" "my-rule" {
    name = "myrule"
    secure = false
}
`, t)
	assert.Len(t, results, 0)
}

func Test_IgnoreLineAboveTheBlockNotMatchingParamString(t *testing.T) {
	scanner.RegisterCheckRule(exampleRule)
	defer scanner.DeregisterCheckRule(exampleRule)

	results := testutil.ScanHCL(`
// tfsec:ignore:*[name=myrule2]
resource "bad" "my-rule" {
    name = "myrule"
    secure = false 
}
`, t)
	assert.Len(t, results, 1)
}

func Test_IgnoreLineAboveTheBlockMatchingParamInt(t *testing.T) {
	scanner.RegisterCheckRule(exampleRule)
	defer scanner.DeregisterCheckRule(exampleRule)

	results := testutil.ScanHCL(`
// tfsec:ignore:*[port=123]
resource "bad" "my-rule" {
   secure = false
   port = 123
}
`, t)
	assert.Len(t, results, 0)
}

func Test_IgnoreLineAboveTheBlockNotMatchingParamInt(t *testing.T) {
	scanner.RegisterCheckRule(exampleRule)
	defer scanner.DeregisterCheckRule(exampleRule)

	results := testutil.ScanHCL(`
// tfsec:ignore:*[port=456]
resource "bad" "my-rule" {
   secure = false 
   port = 123
}
`, t)
	assert.Len(t, results, 1)
}

func Test_IgnoreLineStackedAboveTheBlock(t *testing.T) {
	scanner.RegisterCheckRule(exampleRule)
	defer scanner.DeregisterCheckRule(exampleRule)

	results := testutil.ScanHCL(`
// tfsec:ignore:*
// tfsec:ignore:a
// tfsec:ignore:b
// tfsec:ignore:c
// tfsec:ignore:d
resource "bad" "my-rule" {
   secure = false 
}
`, t)
	assert.Len(t, results, 0)
}

func Test_IgnoreLineStackedAboveTheBlockWithoutMatch(t *testing.T) {
	scanner.RegisterCheckRule(exampleRule)
	defer scanner.DeregisterCheckRule(exampleRule)

	results := testutil.ScanHCL(`
#tfsec:ignore:*

#tfsec:ignore:x
#tfsec:ignore:a
#tfsec:ignore:b
#tfsec:ignore:c
#tfsec:ignore:d
resource "bad" "my-rule" {
   secure = false 
}
`, t)
	assert.Len(t, results, 1)
}

func Test_IgnoreLineStackedAboveTheBlockWithHashesWithoutSpaces(t *testing.T) {
	scanner.RegisterCheckRule(exampleRule)
	defer scanner.DeregisterCheckRule(exampleRule)

	results := testutil.ScanHCL(`
#tfsec:ignore:*
#tfsec:ignore:a
#tfsec:ignore:b
#tfsec:ignore:c
#tfsec:ignore:d
resource "bad" "my-rule" {
   secure = false 
}
`, t)
	assert.Len(t, results, 0)
}

func Test_IgnoreLineStackedAboveTheBlockWithoutSpaces(t *testing.T) {
	scanner.RegisterCheckRule(exampleRule)
	defer scanner.DeregisterCheckRule(exampleRule)

	results := testutil.ScanHCL(`
//tfsec:ignore:*
//tfsec:ignore:a
//tfsec:ignore:b
//tfsec:ignore:c
//tfsec:ignore:d
resource "bad" "my-rule" {
   secure = false 
}
`, t)
	assert.Len(t, results, 0)
}

func Test_IgnoreLineAboveTheLine(t *testing.T) {
	results := testutil.ScanHCL(`

resource "bad" "my-rule" {
	# tfsec:ignore:ABC123
    secure = false
}
`, t)
	assert.Len(t, results, 0)
}

func Test_IgnoreLineLegacy(t *testing.T) {
	scanner.RegisterCheckRule(exampleRule)
	defer scanner.DeregisterCheckRule(exampleRule)
	legacy.InvertedIDs[exampleRule.Base.Rule().LongID()] = "ABC123"
	results := testutil.ScanHCL(`
resource "bad" "my-rule" {
    secure = false # tfsec:ignore:ABC123
}
`, t)
	assert.Len(t, results, 0)
}

func Test_IgnoreLineWithCarriageReturn(t *testing.T) {
	scanner.RegisterCheckRule(exampleRule)
	defer scanner.DeregisterCheckRule(exampleRule)

	legacy.InvertedIDs[exampleRule.Base.Rule().LongID()] = "ABC123"
	results := testutil.ScanHCL(strings.ReplaceAll(`
resource "bad" "my-rule" {
    secure = false # tfsec:ignore:ABC123
}
`, "\n", "\r\n"), t)
	assert.Len(t, results, 0)
}

func Test_IgnoreSpecific(t *testing.T) {

	legacy.InvertedIDs[exampleRule.Base.Rule().LongID()] = "ABC123"

	scanner.RegisterCheckRule(exampleRule)
	defer scanner.DeregisterCheckRule(exampleRule)

	r2 := rule.Rule{
		Base: rules.Register(rules.Rule{
			Provider:  provider.AWSProvider,
			Service:   "service",
			ShortCode: "def456",
			Severity:  severity.High,
		}, nil),
		RequiredLabels: []string{"bad"},
		CheckTerraform: func(resourceBlock *terraform.Block, _ *terraform.Module) (results rules.Results) {
			results.Add(
				"example problem",
				resourceBlock,
			)
			return
		},
	}
	scanner.RegisterCheckRule(r2)
	defer scanner.DeregisterCheckRule(r2)

	results := testutil.ScanHCL(`
	//tfsec:ignore:ABC123
	resource "bad" "my-bad" {
        secure = false
    } 
	//tfsec:ignore:aws-service-abc123
	resource "bad" "my-bad" {

    }
`, t)
	require.Len(t, results, 2)
	assert.Equal(t, results[0].Rule().LongID(), "aws-service-def456")
	assert.Equal(t, results[1].Rule().LongID(), "aws-service-def456")

}

func Test_IgnoreWithExpDateIfDateBreachedThenDontIgnore(t *testing.T) {
	scanner.RegisterCheckRule(exampleRule)
	defer scanner.DeregisterCheckRule(exampleRule)

	results := testutil.ScanHCL(`
resource "bad" "my-rule" {
    secure = false # tfsec:ignore:ABC123:exp:2000-01-02
}
`, t)
	assert.Len(t, results, 1)
}

func Test_IgnoreWithExpDateIfDateNotBreachedThenIgnoreIgnore(t *testing.T) {
	scanner.RegisterCheckRule(exampleRule)
	defer scanner.DeregisterCheckRule(exampleRule)

	results := testutil.ScanHCL(`
resource "bad" "my-rule" {
    secure = false # tfsec:ignore:ABC123:exp:2221-01-02
}
`, t)
	assert.Len(t, results, 0)
}

func Test_IgnoreWithExpDateIfDateInvalidThenDropTheIgnore(t *testing.T) {
	scanner.RegisterCheckRule(exampleRule)
	defer scanner.DeregisterCheckRule(exampleRule)

	results := testutil.ScanHCL(`
resource "bad" "my-rule" {
   secure = false # tfsec:ignore:ABC123:exp:2221-13-02
}
`, t)
	assert.Len(t, results, 1)
}

func Test_IgnoreAboveResourceBlockWithExpDateIfDateNotBreachedThenIgnoreIgnore(t *testing.T) {
	scanner.RegisterCheckRule(exampleRule)
	defer scanner.DeregisterCheckRule(exampleRule)

	results := testutil.ScanHCL(`
#tfsec:ignore:ABC123:exp:2221-01-02
resource "bad" "my-rule" {
}
`, t)
	assert.Len(t, results, 0)
}

func Test_IgnoreAboveResourceBlockWithExpDateAndMultipleIgnoresIfDateNotBreachedThenIgnoreIgnore(t *testing.T) {
	scanner.RegisterCheckRule(exampleRule)
	defer scanner.DeregisterCheckRule(exampleRule)

	results := testutil.ScanHCL(`
# tfsec:ignore:ABC123:exp:2221-01-02
resource "bad" "my-rule" {
	
}
`, t)
	assert.Len(t, results, 0)
}

func Test_IgnoreIgnoreWithExpiryAndWorkspaceAndWorkspaceSupplied(t *testing.T) {
	scanner.RegisterCheckRule(exampleRule)
	defer scanner.DeregisterCheckRule(exampleRule)

	results := testutil.ScanHCL(`
# tfsec:ignore:ABC123:exp:2221-01-02:ws:testworkspace
resource "bad" "my-rule" {
}
`, t, scanner.OptionWithWorkspaceName("testworkspace"))
	assert.Len(t, results, 0)
}

func Test_IgnoreInline(t *testing.T) {
	scanner.RegisterCheckRule(exampleRule)
	defer scanner.DeregisterCheckRule(exampleRule)

	results := testutil.ScanHCL(fmt.Sprintf(`
	resource "bad" "sample" {
		  secure = false # tfsec:ignore:%s
	}
	  `, exampleRule.ID()), t)
	assert.Len(t, results, 0)
}

func Test_IgnoreIgnoreWithExpiryAndWorkspaceButWrongWorkspaceSupplied(t *testing.T) {
	scanner.RegisterCheckRule(exampleRule)
	defer scanner.DeregisterCheckRule(exampleRule)

	results := testutil.ScanHCL(`
# tfsec:ignore:ABC123:exp:2221-01-02:ws:otherworkspace
resource "bad" "my-rule" {
	
}
`, t, scanner.OptionWithWorkspaceName("testworkspace"))
	assert.Len(t, results, 1)
}
