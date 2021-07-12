package parser

import (
	"fmt"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/metrics"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/schema"

	"github.com/hashicorp/hcl/v2"
)

func LoadBlocksFromFile(file *hcl.File) (hcl.Blocks, error) {

	t := metrics.Start(metrics.HCLParse)
	defer t.Stop()

	contents, diagnostics := file.Body.Content(schema.TerraformSchema_0_12)
	if diagnostics != nil && diagnostics.HasErrors() {
		return nil, diagnostics
	}

	if contents == nil {
		return nil, fmt.Errorf("file contents is empty")
	}

	return contents.Blocks, nil
}
