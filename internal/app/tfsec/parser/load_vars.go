package parser

import (
	"fmt"
	"io/ioutil"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/metrics"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/debug"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"

	"github.com/hashicorp/hcl/v2"
)

func LoadTFVars(filenames []string) (map[string]cty.Value, error) {
	combinedVars := make(map[string]cty.Value)

	for _, filename := range filenames {
		vars, err := loadTFVars(filename)
		if err != nil {
			return nil, fmt.Errorf("failed to load the tfvars. %s", err.Error())
		}
		for k, v := range vars {
			combinedVars[k] = v
		}
	}

	return combinedVars, nil
}

func loadTFVars(filename string) (map[string]cty.Value, error) {

	diskTime := metrics.Start(metrics.DiskIO)

	inputVars := make(map[string]cty.Value)

	if filename == "" {
		return inputVars, nil
	}

	debug.Log("loading tfvars-file [%s]", filename)
	src, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	diskTime.Stop()

	hclParseTime := metrics.Start(metrics.HCLParse)
	defer hclParseTime.Stop()

	variableFile, _ := hclsyntax.ParseConfig(src, filename, hcl.Pos{Line: 1, Column: 1})
	attrs, _ := variableFile.Body.JustAttributes()

	for _, attr := range attrs {
		debug.Log("Setting '%s' from tfvars file at %s", attr.Name, filename)
		inputVars[attr.Name], _ = attr.Expr.Value(&hcl.EvalContext{})
	}

	return inputVars, nil
}
