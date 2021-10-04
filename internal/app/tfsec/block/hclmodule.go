package block

import (
	"fmt"
	"strings"
)

type HCLModule struct {
	blocks     Blocks
	rootPath   string
	modulePath string
}

func NewHCLModule(rootPath string, modulePath string, blocks Blocks) Module {
	return &HCLModule{
		blocks:     blocks,
		rootPath:   rootPath,
		modulePath: modulePath,
	}
}

func (c *HCLModule) GetBlocks() Blocks {
	return c.blocks
}

func (c *HCLModule) getBlocksByType(blockType string, label string) Blocks {
	var results Blocks
	for _, block := range c.blocks {
		if block.Type() == blockType && len(block.Labels()) > 0 && block.TypeLabel() == label {
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

func (c *HCLModule) GetReferencedBlock(referringAttr Attribute) (Block, error) {
	for _, ref := range referringAttr.AllReferences() {
		for _, block := range c.blocks {
			if ref.RefersTo(block) {
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
		if attr.ReferencesBlock(originalBlock) {
			results = append(results, block)
		} else {
			for _, ref := range attr.AllReferences() {
				if ref.TypeLabel() == "each" {
					fe := block.GetAttribute("for_each")
					if fe.ReferencesBlock(originalBlock) {
						results = append(results, block)
					}
				}
			}
		}
	}
	return results, nil
}
