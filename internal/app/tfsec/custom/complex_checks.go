package custom

import (
	"fmt"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
)

func checkTags(block block.Block, spec *MatchSpec, module block.Module) bool {
	expectedTag := fmt.Sprintf("%v", spec.MatchValue)

	if block.HasChild("tags") {
		tagsBlock := block.GetAttribute("tags")
		if tagsBlock.Contains(expectedTag) {
			return true
		}
	}

	var alias string
	if block.HasChild("provider") {
		aliasRef, err := block.GetAttribute("provider").Reference()
		if err == nil {
			alias = aliasRef.String()
		}
	}

	awsProviders := module.GetProviderBlocksByProvider("aws", alias)
	for _, providerBlock := range awsProviders {
		if providerBlock.HasChild("default_tags") {
			defaultTags := providerBlock.GetBlock("default_tags")
			if defaultTags.HasChild("tags") {
				tags := defaultTags.GetAttribute("tags")
				if tags.Contains(expectedTag) {
					return true
				}
			}
		}
	}
	return false
}

func ofType(block block.Block, spec *MatchSpec) bool {
	switch value := spec.MatchValue.(type) {
	case []interface{}:
		for _, v := range value {
			if block.TypeLabel() == v {
				return true
			}
		}
	}

	return false
}
