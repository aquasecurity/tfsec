package parser

import (
	"io/ioutil"

	"github.com/tfsec/tfsec/internal/app/tfsec/timer"

	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/tfsec/tfsec/internal/app/tfsec/debug"
	"github.com/zclconf/go-cty/cty"

	"github.com/hashicorp/hcl/v2"
)

func LoadTFVars(filename string) (map[string]cty.Value, error) {

	diskTime := timer.Start(timer.DiskIO)

	inputVars := make(map[string]cty.Value)

	if filename == "" {
		return inputVars, nil
	}

	src, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	diskTime.Stop()

	hclParseTime := timer.Start(timer.HCLParse)
	defer hclParseTime.Stop()

	variableFile, _ := hclsyntax.ParseConfig(src, filename, hcl.Pos{Line: 1, Column: 1})
	attrs, _ := variableFile.Body.JustAttributes()

	for _, attr := range attrs {
		debug.Log("Setting '%s' from tfvars file at %s", attr.Name, filename)
		inputVars[attr.Name], _ = attr.Expr.Value(&hcl.EvalContext{})
	}

	return inputVars, nil
}
