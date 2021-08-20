package block

import (
	"fmt"
	"strings"
)

type HCLModule struct {
	blocks     Blocks
	blockMap   map[string]Blocks
	rootPath   string
	modulePath string
}

func NewHCLModule(rootPath string, modulePath string, blocks Blocks) Module {

	blockMap := make(map[string]Blocks)

	for _, b := range blocks {
		if b.NameLabel() != "" {
			blockMap[b.TypeLabel()] = append(blockMap[b.TypeLabel()], b)
		}
	}

	return &HCLModule{
		blocks:     blocks,
		blockMap:   blockMap,
		rootPath:   rootPath,
		modulePath: modulePath,
	}
}

func (c *HCLModule) GetBlocks() Blocks {
	return c.blocks
}

func (h *HCLModule) GetBlocksByTypeLabel(typeLabel string) Blocks {
	return h.blockMap[typeLabel]
}

func (c *HCLModule) getBlocksByType(blockType string, label string) Blocks {
	var results Blocks
	for _, block := range c.blockMap[label] {
		if block.Type() == blockType {
			results = append(results, block)
		}
	}
	return results
}

func (c *HCLModule) GetResourcesByType(label string) Blocks {
	return c.getBlocksByType("resource", label)
}

func (c *HCLModule) GetDatasByType(label string) Blocks {
	return c.getBlocksByType("data", label)
}

func (c *HCLModule) GetProviderBlocksByProvider(providerName string, alias string) Blocks {
	var results Blocks
	for _, block := range c.blocks {
		if block.Type() == "provider" && len(block.Labels()) > 0 && block.TypeLabel() == providerName {
			if alias != "" {
				if block.HasChild("alias") && block.GetAttribute("alias").Equals(strings.Replace(alias, fmt.Sprintf("%s.", providerName), "", -1)) {
					results = append(results, block)

				}
			} else if block.MissingChild("alias") {
				results = append(results, block)
			}
		}
	}
	return results
}

func (c *HCLModule) GetReferencedBlock(referringAttr Attribute, parentBlock Block) (Block, error) {
	for _, ref := range referringAttr.AllReferences() {
		if ref.TypeLabel() == "each" {
			if forEachAttr := parentBlock.GetAttribute("for_each"); forEachAttr.IsNotNil() {
				if b, err := c.GetReferencedBlock(forEachAttr, parentBlock); err == nil {
					return b, nil
				}
			}
		}
		for _, block := range c.blocks {
			if ref.RefersTo(block.Reference()) {
				return block, nil
			}
			kref := *ref
			kref.SetKeyRaw(parentBlock.Reference().Key())
			fmt.Printf("%#v\n", parentBlock.Reference().String())
			if kref.RefersTo(block.Reference()) {
				return block, nil
			}
		}
	}
	return nil, fmt.Errorf("no referenced block found in '%s'", referringAttr.Name())
}

func (c *HCLModule) GetReferencingResources(originalBlock Block, referencingLabel string, referencingAttributeName string) (Blocks, error) {
	return c.getReferencingBlocks(originalBlock, "resource", referencingLabel, referencingAttributeName)
}

func (c *HCLModule) getReferencingBlocks(originalBlock Block, referencingType string, referencingLabel string, referencingAttributeName string) (Blocks, error) {
	blocks := c.getBlocksByType(referencingType, referencingLabel)
	var results Blocks
	for _, block := range blocks {
		attr := block.GetAttribute(referencingAttributeName)
		if attr == nil {
			continue
		}
		if attr.References(originalBlock.Reference()) {
			results = append(results, block)
		} else {
			for _, ref := range attr.AllReferences() {
				if ref.TypeLabel() == "each" {
					fe := block.GetAttribute("for_each")
					if fe.References(originalBlock.Reference()) {
						results = append(results, block)
					}
				}
			}
		}
	}
	return results, nil
}
