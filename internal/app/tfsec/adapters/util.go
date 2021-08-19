package adapters

import "github.com/aquasecurity/tfsec/internal/app/tfsec/block"

func GetBlocksByTypeLabel(typeLabel string, modules ...block.Module) block.Blocks {
	var blocks block.Blocks
	for _, module := range modules {
		blocks = append(blocks, module.GetBlockByTypeLabel(typeLabel)...)
	}

	return blocks
}
