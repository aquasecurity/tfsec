package block

type Module interface {
	GetBlocks() Blocks
	Ignores() Ignores
	GetBlocksByTypeLabel(typeLabel string) Blocks
	GetResourcesByType(label string) Blocks
	GetDatasByType(label string) Blocks
	GetProviderBlocksByProvider(providerName string, alias string) Blocks
	GetReferencedBlock(referringAttr Attribute, parentBlock Block) (Block, error)
	GetReferencingResources(originalBlock Block, referencingLabel string, referencingAttributeName string) (Blocks, error)
}

type Modules []Module

func (m Modules) GetResourcesByType(typeLabel string) Blocks {
	var blocks Blocks
	for _, module := range m {
		blocks = append(blocks, module.GetResourcesByType(typeLabel)...)
	}

	return blocks
}
