package parser

import (
	"fmt"

	"github.com/tfsec/tfsec/internal/app/tfsec/timer"

	"github.com/hashicorp/hcl/v2"
)

func LoadBlocksFromFile(file *hcl.File) (hcl.Blocks, error) {

	t := timer.Start(timer.HCLParse)
	defer t.Stop()

	contents, diagnostics := file.Body.Content(terraformSchema)
	if diagnostics != nil && diagnostics.HasErrors() {
		return nil, diagnostics
	}

	if contents == nil {
		return nil, fmt.Errorf("file contents is empty")
	}

	return contents.Blocks, nil
}
