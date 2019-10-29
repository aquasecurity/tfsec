package parser

import "github.com/hashicorp/hcl/v2"

// these are specified in the order that terraform will parse them. only currently really important that variables are parsed first
var orderedBlockTypes = []string{
	"variable",
	"locals",
	"provider",
	"resource",
	"data",
	"output",
	"module",
}

// lifted from terraform 0.12 source
var terraformSchema = &hcl.BodySchema{
	Blocks: []hcl.BlockHeaderSchema{
		{
			Type: "terraform",
		},
		{
			Type:       "provider",
			LabelNames: []string{"name"},
		},
		{
			Type:       "variable",
			LabelNames: []string{"name"},
		},
		{
			Type: "locals",
		},
		{
			Type:       "output",
			LabelNames: []string{"name"},
		},
		{
			Type:       "module",
			LabelNames: []string{"name"},
		},
		{
			Type:       "resource",
			LabelNames: []string{"type", "name"},
		},
		{
			Type:       "data",
			LabelNames: []string{"type", "name"},
		},
	},
}
