package parser

import (
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/aquasecurity/defsec/metrics"
	"github.com/aquasecurity/tfsec/internal/pkg/debug"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	hcljson "github.com/hashicorp/hcl/v2/json"
	"github.com/zclconf/go-cty/cty"
)

func LoadTFVars(filenames []string) (map[string]cty.Value, error) {
	combinedVars := make(map[string]cty.Value)

	for _, filename := range filenames {
		vars, err := loadTFVars(filename)
		if err != nil {
			return nil, fmt.Errorf("failed to load the tfvars. %w", err)
		}
		for k, v := range vars {
			combinedVars[k] = v
		}
	}

	return combinedVars, nil
}

func loadTFVars(filename string) (map[string]cty.Value, error) {

	diskTimer := metrics.Timer("timings", "disk i/o")
	diskTimer.Start()

	inputVars := make(map[string]cty.Value)

	if filename == "" {
		return inputVars, nil
	}

	debug.Log("loading tfvars-file [%s]", filename)
	src, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	diskTimer.Stop()

	hclParseTimer := metrics.Timer("timings", "hcl parsing")
	hclParseTimer.Start()
	defer hclParseTimer.Stop()

	var attrs hcl.Attributes
	if strings.HasSuffix(filename, ".json") {
		variableFile, _ := hcljson.Parse(src, filename)
		attrs, _ = variableFile.Body.JustAttributes()
	} else {
		variableFile, _ := hclsyntax.ParseConfig(src, filename, hcl.Pos{Line: 1, Column: 1})
		attrs, _ = variableFile.Body.JustAttributes()
	}

	for _, attr := range attrs {
		debug.Log("Setting '%s' from tfvars file at %s", attr.Name, filename)
		inputVars[attr.Name], _ = attr.Expr.Value(&hcl.EvalContext{})
	}

	return inputVars, nil
}
