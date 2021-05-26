package scanner

import (
	"fmt"
	"strings"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
)

type Context struct {
	blocks parser.Blocks
}

func (c *Context) GetResourcesByType(t string) parser.Blocks {
	var results parser.Blocks
	for _, block := range c.blocks {
		if block.Type() == "resource" && len(block.Labels()) > 0 && block.TypeLabel() == t {
			results = append(results, block)
		}
	}
	return results
}

func (c *Context) GetDatasByType(t string) parser.Blocks {
	var results parser.Blocks
	for _, block := range c.blocks {
		if block.Type() == "data" && len(block.Labels()) > 0 && block.TypeLabel() == t {
			results = append(results, block)
		}
	}
	return results
}

func (c *Context) GetProviderBlocksByProvider(providerName string, alias string) parser.Blocks {
	var results parser.Blocks
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
