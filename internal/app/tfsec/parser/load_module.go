package parser

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/tfsec/tfsec/internal/app/tfsec/timer"

	"github.com/hashicorp/hcl/v2"
	"github.com/tfsec/tfsec/internal/app/tfsec/debug"
	"github.com/zclconf/go-cty/cty"
)

type ModuleInfo struct {
	Name       string
	Path       string
	Definition *Block
	Blocks     Blocks
}

// reads all module blocks and loads the underlying modules, adding blocks to e.moduleBlocks
func LoadModules(blocks Blocks, moduleBasePath string, metadata *ModulesMetadata) []*ModuleInfo {

	var modules []*ModuleInfo

	for _, moduleBlock := range blocks.OfType("module") {
		if moduleBlock.Label() == "" {
			continue
		}
		module, err := loadModule(moduleBlock, moduleBasePath, metadata)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "WARNING: Failed to load module: %s\n", err)
			continue
		}
		modules = append(modules, module)
	}

	return modules
}

// takes in a module "x" {} block and loads resources etc. into e.moduleBlocks - additionally returns variables to add to ["module.x.*"] variables
func loadModule(block *Block, moduleBasePath string, metadata *ModulesMetadata) (*ModuleInfo, error) {

	if block.Label() == "" {
		return nil, fmt.Errorf("module without label at %s", block.Range())
	}

	evalTime := timer.Start(timer.Evaluation)

	var source string
	attrs, _ := block.hclBlock.Body.JustAttributes()
	for _, attr := range attrs {
		if attr.Name == "source" {
			sourceVal, _ := attr.Expr.Value(&hcl.EvalContext{})
			if sourceVal.Type() == cty.String {
				source = sourceVal.AsString()
			}
		}
	}

	evalTime.Stop()

	if source == "" {
		return nil, fmt.Errorf("could not read module source attribute at %s", block.Range().String())
	}

	var modulePath string

	if metadata != nil {
		// if we have module metadata we can parse all the modules as they'll be cached locally!
		for _, module := range metadata.Modules {
			if module.Key == block.Label() || module.Source == source {
				modulePath = filepath.Clean(filepath.Join(moduleBasePath, module.Dir))
				break
			}
		}
	}

	if modulePath == "" {
		// if we have no metadata, we can only support modules available on the local filesystem
		// users wanting this feature should run a `terraform init` before running tfsec to cache all modules locally
		if !strings.HasPrefix(source, "./") && !strings.HasPrefix(source, "../") {
			return nil, fmt.Errorf("missing module with source '%s' -  try to 'terraform init' first", source)
		}

		modulePath = filepath.Join(filepath.Dir(block.Range().Filename), source)
	}

	moduleFiles, err := LoadDirectory(modulePath)
	if err != nil {
		return nil, fmt.Errorf("failed to load module %s: %w", block.Label(), err)
	}

	var blocks Blocks

	for _, file := range moduleFiles {
		fileBlocks, err := LoadBlocksFromFile(file)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "WARNING: HCL error: %s\n", err)
			continue
		}
		if len(fileBlocks) > 0 {
			debug.Log("Added %d blocks from %s...", len(fileBlocks), fileBlocks[0].DefRange.Filename)
		}
		for _, fileBlock := range fileBlocks {
			blocks = append(blocks, NewBlock(fileBlock, nil, block))
		}
	}

	debug.Log("Loaded module '%s' (requested at %s)", modulePath, block.Range())

	return &ModuleInfo{
		Name:       block.Label(),
		Path:       modulePath,
		Definition: block,
		Blocks:     blocks,
	}, nil
}
