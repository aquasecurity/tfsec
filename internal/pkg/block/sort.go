package block

import (
	"sort"
)

func SortByHierarchy(blocks Blocks) {
	c := &counter{
		cache: make(map[string]int),
	}
	sort.Slice(blocks, func(i, j int) bool {
		a := blocks[i]
		b := blocks[j]
		return c.countBlockRecursion(a, blocks, 0) < c.countBlockRecursion(b, blocks, 0)
	})
}

type counter struct {
	cache map[string]int
}

func (c *counter) countBlockRecursion(block *Block, blocks Blocks, count int) int {
	if cached, ok := c.cache[block.GetMetadata().Reference().String()]; ok {
		return cached
	}
	var maxCount int
	var hasRecursion bool
	for _, attrName := range []string{"for_each", "count"} {
		if attr := block.GetAttribute(attrName); attr.IsNotNil() {
			hasRecursion = true
			for _, other := range blocks {
				if attr.ReferencesBlock(other) {
					depth := c.countBlockRecursion(other, blocks, count)
					if depth > maxCount {
						maxCount = depth
					}
				}
			}
		}
	}
	if hasRecursion {
		maxCount++
	}
	result := maxCount + count
	c.cache[block.GetMetadata().Reference().String()] = result
	return result
}
