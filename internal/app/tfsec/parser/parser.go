package parser

import (
	"github.com/tfsec/tfsec/internal/app/tfsec/debug"
	"io/ioutil"
	"path/filepath"
)

// Parser is a tool for parsing terraform templates at a given file system location
type Parser struct {
	fullPath   string
	tfvarsPath string
}

// New creates a new Parser
func New(fullPath string, tfvarsPath string) *Parser {
	return &Parser{
		fullPath:   fullPath,
		tfvarsPath: tfvarsPath,
	}
}

// ParseDirectory parses all terraform files within a given directory
func (parser *Parser) ParseDirectory() (Blocks, error) {

	debug.Log("Finding Terraform subdirectories...")
	subdirectories, err := parser.getSubdirectories(parser.fullPath)
	if err != nil {
		return nil, err
	}

	var blocks Blocks

	for _, dir := range subdirectories {
		debug.Log("Beginning parse for directory '%s'...", parser.fullPath)
		files, err := LoadDirectory(dir)
		if err != nil {
			return nil, err
		}

		for _, file := range files {
			fileBlocks, err := LoadBlocksFromFile(file)
			if err != nil {
				return nil, err
			}
			if len(fileBlocks) > 0 {
				debug.Log("Added %d blocks from %s...", len(fileBlocks), fileBlocks[0].DefRange.Filename)
			}
			for _, fileBlock := range fileBlocks {
				blocks = append(blocks, NewBlock(fileBlock, nil, nil))
			}
		}
	}

	debug.Log("Loading TFVars...")
	inputVars, err := LoadTFVars(parser.tfvarsPath)
	if err != nil {
		return nil, err
	}

	debug.Log("Loading module metadata...")
	modulesMetadata, _ := LoadModuleMetadata(parser.fullPath)

	debug.Log("Loading modules...")
	modules := LoadModules(blocks, parser.fullPath, modulesMetadata)

	debug.Log("Evaluating expressions...")
	evaluator := NewEvaluator(parser.fullPath, blocks, inputVars, modulesMetadata, modules)
	return evaluator.EvaluateAll()
}

func (parser *Parser) getSubdirectories(path string) ([]string, error) {
	entries, err := ioutil.ReadDir(path)
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		if !entry.IsDir() && filepath.Ext(entry.Name()) == ".tf" {
			debug.Log("Found qualifying subdirctory containing .tf files: %s", path)
			return []string{path}, nil
		}
	}

	var results []string

	for _, entry := range entries {
		if entry.IsDir() {
			dirs, err := parser.getSubdirectories(filepath.Join(path, entry.Name()))
			if err != nil {
				return nil, err
			}
			results = append(results, dirs...)
		}
	}

	return results, nil
}
