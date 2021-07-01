package hclcontext

import (
	"fmt"
	"strings"

	"github.com/tfsec/tfsec/internal/app/tfsec/block"
)

type Context struct {
	blocks block.Blocks
}

func New(blocks block.Blocks) *Context {
	return &Context{
		blocks: blocks,
	}
}

func (c *Context) GetResourcesByType(t string) block.Blocks {
	var results block.Blocks
	for _, block := range c.blocks {
		if block.Type() == "resource" && len(block.Labels()) > 0 && block.TypeLabel() == t {
			results = append(results, block)
		}
	}
	return results
}

func (c *Context) GetDatasByType(t string) block.Blocks {
	var results block.Blocks
	for _, block := range c.blocks {
		if block.Type() == "data" && len(block.Labels()) > 0 && block.TypeLabel() == t {
			results = append(results, block)
		}
	}
	return results
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

func (c *Context) GetReferencedBlock(referringAttr *block.Attribute) (*block.Block, error) {
	resType, err := referringAttr.GetReferencedResourceBlockType()
	if err != nil {
		return nil, err
	}
	resName, err := referringAttr.GetReferencedResourceBlocksName()
	if err != nil {
		return nil, err
	}

	for _, resource := range c.GetResourcesByType(resType) {
		if resource.NameLabel() == resName {
			return resource, nil
		}
	}

	return nil, fmt.Errorf("did not find a suitable block to reference")
}
