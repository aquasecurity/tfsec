package parser

import (
	"fmt"
	"github.com/tfsec/tfsec/internal/app/tfsec/metrics"
	"os"
	"path/filepath"
	"strings"

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
func LoadModules(blocks Blocks, projectBasePath string, metadata *ModulesMetadata) []*ModuleInfo {

	var modules []*ModuleInfo

	for _, moduleBlock := range blocks.OfType("module") {
		if moduleBlock.Label() == "" {
			continue
		}
		module, err := loadModule(moduleBlock, projectBasePath, metadata)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "WARNING: Failed to load module: %s\n", err)
			continue
		}
		metrics.Add(metrics.ModuleBlocksLoaded, len(module.Blocks))
		modules = append(modules, module)
	}

	return modules
}

// takes in a module "x" {} block and loads resources etc. into e.moduleBlocks - additionally returns variables to add to ["module.x.*"] variables
func loadModule(block *Block, projectBasePath string, metadata *ModulesMetadata) (*ModuleInfo, error) {

	if block.Label() == "" {
		return nil, fmt.Errorf("module without label at %s", block.Range())
	}

	evalTime := metrics.Start(metrics.Evaluation)

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
			if module.Source == source {
				modulePath = filepath.Clean(filepath.Join(projectBasePath, module.Dir))
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

		modulePath = reconstructPath(projectBasePath, source)
	}

	blocks := Blocks{}
	err := getModuleBlocks(block, modulePath, &blocks)
	if err != nil {
		return nil, err
	}
	debug.Log("Loaded module '%s' (requested at %s)", modulePath, block.Range())
	metrics.Add(metrics.ModuleLoadCount, 1)

	return &ModuleInfo{
		Name:       block.Label(),
		Path:       modulePath,
		Definition: block,
		Blocks:     blocks,
	}, nil
}

// This function takes the relative source path provided by `source` and reconstructs the absolute path
// based on the project base path and the relative source path
func reconstructPath(projectBasePath string, source string) string {

	// get the parent directory until we reach the shared parent directory
	for strings.HasPrefix(source, "../") {
		projectBasePath = filepath.Dir(projectBasePath)
		source = strings.TrimPrefix(source, "../")
	}
	return filepath.Join(projectBasePath, source)
}

func getModuleBlocks(block *Block, modulePath string, blocks *Blocks) error {
	moduleFiles, err := LoadDirectory(modulePath)
	if err != nil {
		return fmt.Errorf("failed to load module %s: %w", block.Label(), err)
	}

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
			*blocks = append(*blocks, NewBlock(fileBlock, nil, block))
		}
	}
	return nil
}

