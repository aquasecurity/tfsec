package parser

import (
	"fmt"
	"io/ioutil"
	"path/filepath"
	"strings"

	"github.com/zclconf/go-cty/cty"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclparse"
)

const maxContextIterations = 32

type Parser struct {
	hclParser *hclparse.Parser
}

func New() *Parser {
	return &Parser{
		hclParser: hclparse.NewParser(),
	}
}

func (parser *Parser) ParseDirectory(path string) (hcl.Blocks, *hcl.EvalContext, error) {

	if err := parser.recursivelyParseDirectory(path); err != nil {
		return nil, nil, err
	}

	var blocks []*hcl.Block

	for _, file := range parser.hclParser.Files() {
		fileBlocks, err := parser.parseFile(file)
		if err != nil {
			return nil, nil, err
		}
		blocks = append(blocks, fileBlocks...)
	}

	return blocks, parser.buildEvaluationContext(blocks), nil
}

func (parser *Parser) ParseFile(path string) (hcl.Blocks, *hcl.EvalContext, error) {
	parsedFile, diagnostics := parser.hclParser.ParseHCLFile(path)
	if diagnostics != nil && diagnostics.HasErrors() {
		return nil, nil, diagnostics
	}

	blocks, err := parser.parseFile(parsedFile)
	if err != nil {
		return nil, nil, err
	}

	return blocks, parser.buildEvaluationContext(blocks), nil
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

func (parser *Parser) recursivelyParseDirectory(path string) error {

	files, err := ioutil.ReadDir(path)
	if err != nil {
		return err
	}
	for _, file := range files {
		fullPath := filepath.Join(path, file.Name())
		if file.IsDir() {
			if err := parser.recursivelyParseDirectory(fullPath); err != nil {
				return err
			}
		} else if strings.HasSuffix(file.Name(), ".tf") {
			_, diagnostics := parser.hclParser.ParseHCLFile(fullPath)
			if diagnostics != nil && diagnostics.HasErrors() {
				return diagnostics
			}
		}
	}

	return nil
}

// BuildEvaluationContext creates an *hcl.EvalContext by parsing values for all terraform variables (where available) then interpolating values into resource, local and data blocks until all possible values can be constructed
func (parser *Parser) buildEvaluationContext(blocks hcl.Blocks) *hcl.EvalContext {
	ctx := hcl.EvalContext{
		Variables: make(map[string]cty.Value),
	}
	for i := 0; i < maxContextIterations; i++ {
		clean := true
		for _, blockType := range orderedBlockTypes {
			clean = clean && parser.addToContextByBlockType(&ctx, blocks, blockType)
		}
		if clean {
			break
		}
	}
	return &ctx
}

// returns true if all evaluations were successful
func (parser *Parser) readValues(ctx *hcl.EvalContext, block *hcl.Block) (cty.Value, bool) {

	values := make(map[string]cty.Value)

	attributes, diagnostics := block.Body.JustAttributes()
	if diagnostics != nil && diagnostics.HasErrors() {
		return cty.ObjectVal(values), false
	}

	success := true

	for _, attribute := range attributes {
		val, diag := attribute.Expr.Value(ctx)
		if diag != nil && diag.HasErrors() {
			success = false
			continue
		}
		values[attribute.Name] = val
	}

	return cty.ObjectVal(values), success
}

// returns true if all evaluations were successful
func (parser *Parser) addToContextByBlockType(ctx *hcl.EvalContext, blocks hcl.Blocks, blockType string) bool {

	success := true

	blocksOfType := blocks.OfType(blockType)
	alias := blockType

	values := make(map[string]cty.Value)
	for _, block := range blocksOfType {

		switch block.Type {
		case "variable": // variables are special in that their value comes from the "default" attribute
			alias = "var"
			fallthrough
		case "output":
			if len(block.Labels) < 1 {
				continue
			}
			attributes, diagnostics := block.Body.JustAttributes()
			if diagnostics != nil && diagnostics.HasErrors() {
				success = false
				continue
			}
			if def, exists := attributes["default"]; exists {
				var diag hcl.Diagnostics
				values[block.Labels[0]], diag = def.Expr.Value(nil)
				if diag != nil && diag.HasErrors() {
					success = false
				}
			}
		case "locals":
			alias = "local"
			localValues, partialSuccess := parser.readValues(ctx, block)
			if !partialSuccess {
				success = false
			}
			for key, val := range localValues.AsValueMap() {
				values[key] = val
			}
		case "provider", "module":
			if len(block.Labels) < 1 {
				continue
			}
			var partialSuccess bool
			values[block.Labels[0]], partialSuccess = parser.readValues(ctx, block)
			if !partialSuccess {
				success = false
			}
		case "resource":
			alias = ""
			fallthrough
		case "data":

			if len(block.Labels) < 2 {
				continue
			}

			blockMap, ok := values[block.Labels[0]]
			if !ok {
				values[block.Labels[0]] = cty.ObjectVal(make(map[string]cty.Value))
				blockMap = values[block.Labels[0]]
			}

			valueMap := blockMap.AsValueMap()
			if valueMap == nil {
				valueMap = make(map[string]cty.Value)
			}

			var partialSuccess bool
			valueMap[block.Labels[1]], partialSuccess = parser.readValues(ctx, block)
			values[block.Labels[0]] = cty.ObjectVal(valueMap)
			if !partialSuccess {
				success = false
			}
		}

	}

	if alias == "" {
		for key, val := range values {
			ctx.Variables[key] = val
		}
	} else {
		existing, exists := ctx.Variables[alias]
		if exists {
			existingMap := existing.AsValueMap()
			for key, val := range values {
				existingMap[key] = val
			}
			ctx.Variables[alias] = cty.ObjectVal(existingMap)
		} else {
			ctx.Variables[alias] = cty.ObjectVal(values)
		}
	}
	return success
}
