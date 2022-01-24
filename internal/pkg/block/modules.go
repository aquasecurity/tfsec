package block

import "fmt"

type Modules []*Module

type ResourceIDResolutions map[string]bool

func (r ResourceIDResolutions) Resolve(id string) {
	r[id] = true
}

func (r ResourceIDResolutions) Orphans() (orphanIDs []string) {
	for id, resolved := range r {
		if !resolved {
			orphanIDs = append(orphanIDs, id)
		}
	}
	return orphanIDs
}

func (m Modules) GetResourcesByType(typeLabel ...string) Blocks {
	var blocks Blocks
	for _, module := range m {
		blocks = append(blocks, module.GetResourcesByType(typeLabel...)...)
	}

	return blocks
}

func (m Modules) GetChildResourceIDMapByType(typeLabels ...string) ResourceIDResolutions {
	blocks := m.GetResourcesByType(typeLabels...)

	idMap := make(map[string]bool)
	for _, block := range blocks {
		idMap[block.ID()] = false
	}

	return idMap
}

func (m Modules) GetReferencedBlock(referringAttr *Attribute, parentBlock *Block) (*Block, error) {
	for _, module := range m {
		b, err := module.GetReferencedBlock(referringAttr, parentBlock)
		if err == nil {
			return b, nil
		}
	}
	return nil, fmt.Errorf("block not found")
}

func (m Modules) GetReferencingResources(originalBlock *Block, referencingLabel string, referencingAttributeName string) Blocks {
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
