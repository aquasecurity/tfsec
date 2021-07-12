package parser

import (
	"fmt"
	"strings"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/debug"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/metrics"

	"io/ioutil"
	"os"
	"path/filepath"
)

// Parser is a tool for parsing terraform templates at a given file system location
type Parser struct {
	initialPath    string
	tfvarsPaths    []string
	stopOnFirstTf  bool
	stopOnHCLError bool
}

// New creates a new Parser
func New(initialPath string, options ...Option) *Parser {
	p := &Parser{
		initialPath:   initialPath,
		stopOnFirstTf: true,
	}

	for _, option := range options {
		option(p)
	}

	return p
}

// ParseDirectory parses all terraform files within a given directory
func (parser *Parser) ParseDirectory() (block.Blocks, error) {

	debug.Log("Finding Terraform subdirectories...")
	t := metrics.Start(metrics.DiskIO)
	subdirectories, err := parser.getSubdirectories(parser.initialPath)
	if err != nil {
		return nil, err
	}
	t.Stop()

	var blocks block.Blocks

	for _, dir := range subdirectories {
		debug.Log("Beginning parse for directory '%s'...", dir)
		files, err := LoadDirectory(dir, parser.stopOnHCLError)
		if err != nil {
			return nil, err
		}

		for _, file := range files {
			fileBlocks, err := LoadBlocksFromFile(file)
			if err != nil {
				if parser.stopOnHCLError {
					return nil, err
				}
				_, _ = fmt.Fprintf(os.Stderr, "WARNING: HCL error: %s\n", err)
				continue
			}
			if len(fileBlocks) > 0 {
				debug.Log("Added %d blocks from %s...", len(fileBlocks), fileBlocks[0].DefRange.Filename)
			}
			for _, fileBlock := range fileBlocks {
				blocks = append(blocks, block.NewHCLBlock(fileBlock, nil, nil))
			}
		}
	}

	metrics.Add(metrics.BlocksLoaded, len(blocks))

	if len(blocks) == 0 && parser.stopOnFirstTf {
		return nil, nil
	}

	tfPath := parser.initialPath
	if len(subdirectories) > 0 && parser.stopOnFirstTf {
		tfPath = subdirectories[0]
		debug.Log("Project root set to '%s'...", tfPath)
	}

	debug.Log("Loading TFVars...")

	inputVars, err := LoadTFVars(parser.tfvarsPaths)
	if err != nil {
		return nil, err
	}

	debug.Log("Loading module metadata...")
	t = metrics.Start(metrics.DiskIO)
	modulesMetadata, _ := LoadModuleMetadata(tfPath)
	t.Stop()

	debug.Log("Loading modules...")
	modules := LoadModules(blocks, tfPath, modulesMetadata, parser.stopOnHCLError)
	var visited []*visitedModule

	debug.Log("Evaluating expressions...")
	evaluator := NewEvaluator(tfPath, tfPath, blocks, inputVars, modulesMetadata, modules, visited, parser.stopOnHCLError)
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

	var results []string
	for _, entry := range entries {
		if !entry.IsDir() && (filepath.Ext(entry.Name()) == ".tf" || strings.HasSuffix(entry.Name(), ".tf.json")) {
			debug.Log("Found qualifying subdirectory containing .tf files: %s", path)
			results = append(results, path)
			if parser.stopOnFirstTf {
				return results, nil
			}
		}
	}

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
