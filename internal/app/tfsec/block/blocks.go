package block

type Blocks []Block

func (blocks Blocks) OfType(t string) Blocks {
	var results []Block
	for _, block := range blocks {
		if block.Type() == t {
			results = append(results, block)
		}
	}
	return results
}
