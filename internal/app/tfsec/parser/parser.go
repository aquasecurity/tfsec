package parser

import (
	"fmt"

	"github.com/tfsec/tfsec/internal/app/tfsec/debug"

	"github.com/hashicorp/hcl/v2"
)

// Parser is a tool for parsing terraform templates at a given file system location
type Parser struct {
	fullPath            string
	excludedDirectories []string
	tfvarsPath          string
}

// New creates a new Parser
func New(fullPath string, tfvarsPath string, excludedDirectories []string) *Parser {
	return &Parser{
		fullPath:            fullPath,
		excludedDirectories: excludedDirectories,
		tfvarsPath:          tfvarsPath,
	}
}

// ParseDirectory recursively parses all terraform files within a given directory
func (parser *Parser) ParseDirectory() (Blocks, error) {

	debug.Log("Beginning recursive parse of %s...", parser.fullPath)
	files, err := LoadDirectory(parser.fullPath, parser.excludedDirectories)
	if err != nil {
		return nil, err
	}

	var blocks Blocks

	for _, file := range files {
		fileBlocks, err := parser.parseFile(file)
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

	inputVars, err := LoadTFVars(parser.tfvarsPath)
	if err != nil {
		return nil, err
	}

	evaluator := NewEvaluator(parser.fullPath, blocks, inputVars)
	return evaluator.EvaluateAll()
}

func (parser *Parser) parseFile(file *hcl.File) (hcl.Blocks, error) {

	contents, diagnostics := file.Body.Content(terraformSchema)
	if diagnostics != nil && diagnostics.HasErrors() {
		return nil, diagnostics
	}

	if contents == nil {
		return nil, fmt.Errorf("file contents is empty")
	}

	return contents.Blocks, nil
}

//
//func (parser *Parser) parseModuleBlock(
//	block *hcl.Block,
//	parentContext *hcl.EvalContext,
//	rootPath string,
//	pc parseCache,
//	excludedDirectories []string,
//) (Blocks, cty.Value) {
//
//	if len(block.Labels) == 0 {
//		return nil, cty.NilVal
//	}
//
//	inputVars := make(map[string]cty.Value)
//
//	var source string
//	attrs, _ := block.Body.JustAttributes()
//	for _, attr := range attrs {
//
//		inputVars[attr.Name], _ = attr.Expr.Value(parentContext)
//
//		if attr.Name == "source" {
//			sourceVal, _ := attr.Expr.Value(parentContext)
//			if sourceVal.Type() == cty.String {
//				source = sourceVal.AsString()
//			}
//		}
//	}
//
//	if source == "" {
//		return nil, cty.NilVal
//	}
//
//	if !strings.HasPrefix(source, "./") && !strings.HasPrefix(source, "../") {
//		// TODO support module registries/github etc.
//		return nil, cty.NilVal
//	}
//
//	path := filepath.Join(rootPath, source)
//	if result, ok := pc.lookupResult(path); ok {
//		return result.Blocks, result.Value
//	}
//
//	// We need to respect the module's path if it's local to the filesystem.
//	// If the `rootPath` != `modulePath` then this means that we're not
//	// parsing this module from the correct working directory, and so
//	// parsing will break. In that case, reset the path to the path known
//	// to the module so that local paths will work as expected.
//	modulePath := filepath.Dir(block.DefRange.Filename)
//	if rootPath != modulePath {
//		path = modulePath
//	}
//
//	subParser := New()
//
//	if err := subParser.recursivelyParseDirectory(path, pc, excludedDirectories); err != nil {
//		return nil, cty.NilVal
//	}
//
//	var blocks []*hcl.Block
//
//	for _, file := range subParser.hclParser.Files() {
//		fileBlocks, err := subParser.parseFile(file)
//		if err != nil {
//			return nil, cty.NilVal
//		}
//		blocks = append(blocks, fileBlocks...)
//	}
//
//	childModules, ctx := subParser.buildEvaluationContext(blocks, path, inputVars, block, pc, excludedDirectories)
//	parseResult := ParseResult{
//		Blocks: childModules.RemoveDuplicates(),
//		Value:  cty.ObjectVal(ctx.Variables),
//	}
//
//	pc.storeResult(path, parseResult)
//	return parseResult.Blocks, parseResult.Value
//}
