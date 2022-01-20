package block

import "fmt"

type Module interface {
	GetBlocks() Blocks
	Ignores() Ignores
	GetBlocksByTypeLabel(typeLabel string) Blocks
	GetResourcesByType(labels ...string) Blocks
	GetResourcesByIDs(ids ...string) Blocks
	GetDatasByType(label string) Blocks
	GetProviderBlocksByProvider(providerName string, alias string) Blocks
	GetReferencedBlock(referringAttr Attribute, parentBlock Block) (Block, error)
	GetReferencingResources(originalBlock Block, referencingLabel string, referencingAttributeName string) Blocks
	GetsModulesBySource(moduleSource string) (Blocks, error)
}

type Modules []Module

func (m Modules) GetResourcesByType(typeLabel ...string) Blocks {
	var blocks Blocks
	for _, module := range m {
		blocks = append(blocks, module.GetResourcesByType(typeLabel...)...)
	}

	return blocks
}

func (m Modules) GetChildResourceIDMapByType(typeLabel string) map[string]bool {
	blocks := m.GetResourcesByType(typeLabel)

	idMap := make(map[string]bool)
	for _, block := range blocks {
		idMap[block.ID()] = false
	}

	return idMap
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

func (m Modules) GetReferencingResources(originalBlock Block, referencingLabel string, referencingAttributeName string) Blocks {
	var blocks Blocks
	for _, module := range m {
		blocks = append(blocks, module.GetReferencingResources(originalBlock, referencingLabel, referencingAttributeName)...)
	}

	return blocks
}

func (m Modules) GetBlocks() Blocks {
	var blocks Blocks
	for _, module := range m {
		blocks = append(blocks, module.GetBlocks()...)
	}
	return blocks
}

func (m Modules) GetResourceByIDs(id ...string) Blocks {
	var blocks Blocks
	for _, module := range m {
		blocks = append(blocks, module.GetResourcesByIDs(id...)...)
	}

	return blocks
}
