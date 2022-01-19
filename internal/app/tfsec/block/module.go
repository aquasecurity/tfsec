package block

import "fmt"

type Module interface {
	GetBlocks() Blocks
	Ignores() Ignores
	GetBlocksByTypeLabel(typeLabel string) Blocks
	GetResourcesByType(labels ...string) Blocks
	GetDatasByType(label string) Blocks
	GetProviderBlocksByProvider(providerName string, alias string) Blocks
	GetReferencedBlock(referringAttr Attribute, parentBlock Block) (Block, error)
	GetReferencingResources(originalBlock Block, referencingLabel string, referencingAttributeName string) Blocks
	GetsModulesBySource(moduleSource string) (Blocks, error)
}

type Modules []Module

func (m Modules) GetResourcesByType(typeLabel string) Blocks {
	var blocks Blocks
	for _, module := range m {
		blocks = append(blocks, module.GetResourcesByType(typeLabel)...)
	}

	return blocks
}

func (m Modules) GetReferencedBlock(referringAttr Attribute, parentBlock Block) (Block, error) {
	for _, module := range m {
		b, err := module.GetReferencedBlock(referringAttr, parentBlock)
		if err == nil {
			return b, nil
		}
	}
	return nil, fmt.Errorf("block not found")
}

func (m Modules) GetBlocks() Blocks {
	var blocks Blocks
	for _, module := range m {
		blocks = append(blocks, module.GetBlocks()...)
	}
	return blocks
}
