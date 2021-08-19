package block

type Module interface {
	GetBlocks() Blocks
	GetBlockByTypeLabel(typeLabel string) Blocks
	GetResourcesByType(label string) Blocks
	GetDatasByType(label string) Blocks
	GetProviderBlocksByProvider(providerName string, alias string) Blocks
	GetReferencedBlock(referringAttr Attribute) (Block, error)
	GetReferencingResources(originalBlock Block, referencingLabel string, referencingAttributeName string) (Blocks, error)
}
