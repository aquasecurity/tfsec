package parser

import (
	"fmt"
	"github.com/tfsec/tfsec/internal/app/tfsec/debug"
	"github.com/tfsec/tfsec/internal/app/tfsec/metrics"

	"io/ioutil"
	"os"
	"path/filepath"
)

type ParserOption int

const (
	DontSearchTfFiles ParserOption = iota
)

// Parser is a tool for parsing terraform templates at a given file system location
type Parser struct {
	initialPath    string
	tfvarsPath     string
	lookForTfFiles bool
}

// New creates a new Parser
func New(initialPath string, tfvarsPath string, options ...ParserOption) *Parser {
	p := &Parser{
		initialPath: initialPath,
		tfvarsPath:  tfvarsPath,
		lookForTfFiles: true,
	}

	for _, option := range options {
		switch option {
		case DontSearchTfFiles:
			p.lookForTfFiles = false
		}
	}
	return p
}

// ParseDirectory parses all terraform files within a given directory
func (parser *Parser) ParseDirectory() (Blocks, error) {

	debug.Log("Finding Terraform subdirectories...")
	t := metrics.Start(metrics.DiskIO)
	subdirectories, err := parser.getSubdirectories(parser.initialPath)
	if err != nil {
		return nil, err
	}
	t.Stop()

	var blocks Blocks

	for _, dir := range subdirectories {
		debug.Log("Beginning parse for directory '%s'...", dir)
		files, err := LoadDirectory(dir)
		if err != nil {
			return nil, err
		}

		for _, file := range files {
			fileBlocks, err := LoadBlocksFromFile(file)
			if err != nil {
				_, _ = fmt.Fprintf(os.Stderr, "WARNING: HCL error: %s\n", err)
				continue
			}
			if len(fileBlocks) > 0 {
				debug.Log("Added %d blocks from %s...", len(fileBlocks), fileBlocks[0].DefRange.Filename)
			}
			for _, fileBlock := range fileBlocks {
				blocks = append(blocks, NewBlock(fileBlock, nil, nil))
			}
		}
	}

	metrics.Add(metrics.BlocksLoaded, len(blocks))

	if len(blocks) == 0 {
		return nil, nil
	}

	tfPath := parser.initialPath
	if len(subdirectories) > 0 && parser.lookForTfFiles {
		tfPath = subdirectories[0]
		debug.Log("Project root set to '%s'...", tfPath)
	}

	debug.Log("Loading TFVars...")
	t = metrics.Start(metrics.DiskIO)
	inputVars, err := LoadTFVars(parser.tfvarsPath)
	if err != nil {
		return nil, err
	}
	t.Stop()

	debug.Log("Loading module metadata...")
	t = metrics.Start(metrics.DiskIO)
	modulesMetadata, _ := LoadModuleMetadata(tfPath)
	t.Stop()

	debug.Log("Loading modules...")
	modules := LoadModules(blocks, tfPath, modulesMetadata)

	debug.Log("Evaluating expressions...")
	evaluator := NewEvaluator(tfPath, tfPath, blocks, inputVars, modulesMetadata, modules)
	evaluatedBlocks, err := evaluator.EvaluateAll()
	if err != nil {
		return nil, err
	}
	metrics.Add(metrics.BlocksEvaluated, len(evaluatedBlocks))
	return evaluatedBlocks, nil

}

func (parser *Parser) getSubdirectories(path string) ([]string, error) {
	entries, err := ioutil.ReadDir(path)
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		if !entry.IsDir() && filepath.Ext(entry.Name()) == ".tf" {
			debug.Log("Found qualifying subdirectory containing .tf files: %s", path)
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
