package scanner

import "github.com/tfsec/tfsec/internal/app/tfsec/parser"

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
