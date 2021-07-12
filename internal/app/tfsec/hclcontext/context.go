package hclcontext

import (
	"fmt"
	"strings"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

type Context struct {
	blocks block.Blocks
}

func New(blocks block.Blocks) *Context {
	return &Context{
		blocks: blocks,
	}
}

func (c *Context) getBlocksByType(blockType string, label string) block.Blocks {
	var results block.Blocks
	for _, block := range c.blocks {
		if block.Type() == blockType && len(block.Labels()) > 0 && block.TypeLabel() == label {
			results = append(results, block)
		}
	}
	return results
}

func (c *Context) GetResourcesByType(label string) block.Blocks {
	return c.getBlocksByType("resource", label)
}

func (c *Context) GetDatasByType(label string) block.Blocks {
	return c.getBlocksByType("data", label)
}

func (c *Context) GetProviderBlocksByProvider(providerName string, alias string) block.Blocks {
	var results block.Blocks
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

func (c *Context) GetReferencedBlock(referringAttr block.Attribute) (block.Block, error) {
	ref, err := referringAttr.Reference()
	if err != nil {
		return nil, err
	}
	for _, block := range c.blocks {
		if ref.RefersTo(block) {
			return block, nil
		}
	}
	return nil, fmt.Errorf("no block found for reference %s", ref)
}

func (c *Context) GetReferencingResources(originalBlock block.Block, referencingLabel string, referencingAttributeName string) (block.Blocks, error) {
	return c.getReferencingBlocks(originalBlock, "resource", referencingLabel, referencingAttributeName)
}

func (c *Context) getReferencingBlocks(originalBlock block.Block, referencingType string, referencingLabel string, referencingAttributeName string) (block.Blocks, error) {
	blocks := c.getBlocksByType(referencingType, referencingLabel)
	var results block.Blocks
	for _, block := range blocks {
		attr := block.GetAttribute(referencingAttributeName)
		if attr == nil {
			continue
		}
		if attr.ReferencesBlock(originalBlock) {
			results = append(results, block)
		}
	}
	return results, nil
}
