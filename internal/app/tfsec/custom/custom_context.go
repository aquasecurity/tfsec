package custom

import "github.com/aquasecurity/tfsec/internal/app/tfsec/block"

type customCheckVariables map[string]string

type customContext struct {
	module    block.Module
	variables customCheckVariables
}

func NewEmptyCustomContext() *customContext {
	return &customContext{
		module:    nil,
		variables: make(customCheckVariables),
	}
}

func NewCustomContext(module block.Module) *customContext {
	return &customContext{
		module:    module,
		variables: make(customCheckVariables),
	}
}

func NewCustomContextWithVariables(module block.Module, variables customCheckVariables) *customContext {
	return &customContext{
		module:    module,
		variables: variables,
	}
}
