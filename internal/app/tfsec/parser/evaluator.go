package parser

import (
	"fmt"
	"github.com/hashicorp/hcl/v2"
	"github.com/tfsec/tfsec/internal/app/tfsec/debug"
	"github.com/zclconf/go-cty/cty"
	"os"
	"path/filepath"
	"reflect"
	"strings"
)

const maxContextIterations = 32

type Evaluator struct {
	ctx            *hcl.EvalContext
	blocks         Blocks
	modules        []*ModuleInfo
	inputVars      map[string]cty.Value
	moduleMetadata *ModulesMetadata
	path           string
	moduleBasePath string
}

func NewEvaluator(path string, blocks Blocks, inputVars map[string]cty.Value, moduleMetadata *ModulesMetadata) *Evaluator {

	ctx := &hcl.EvalContext{
		Variables: make(map[string]cty.Value),
		Functions: Functions(path),
	}

	// attach context to blocks
	for _, block := range blocks {
		block.ctx = ctx
	}

	return &Evaluator{
		path: path,
		moduleBasePath: path,
		ctx:       ctx,
		blocks:    blocks,
		inputVars: inputVars,
		moduleMetadata: moduleMetadata,
	}
}

func(e *Evaluator) SetModuleBasePath(path string) {
	e.moduleBasePath = path
}

/*
blocks hcl.Blocks,
inputVars map[string]cty.Value,
parentBlock *hcl.Block,
*/

func (e *Evaluator) evaluateStep(i int) {

	debug.Log("Starting iteration %d of context evaluation...", i+1)

	e.ctx.Variables["var"] = e.getValuesByBlockType("variable")
	e.ctx.Variables["local"] = e.getValuesByBlockType("locals")
	e.ctx.Variables["provider"] = e.getValuesByBlockType("provider")

	resources := e.getValuesByBlockType("resource")
	for key, resource := range resources.AsValueMap() {
		e.ctx.Variables[key] = resource
	}

	e.ctx.Variables["data"] = e.getValuesByBlockType("data")
	e.ctx.Variables["output"] = e.getValuesByBlockType("output")

	e.evaluateModules()
}

// reads all module blocks and loads the underlying modules, adding blocks to e.moduleBlocks
func(e *Evaluator) loadModules() error {

	for _, moduleBlock := range e.blocks.OfType("module") {
		if moduleBlock.Label() == "" {
			continue
		}
		module, err := e.loadModule(moduleBlock)
		if err != nil {
			_, _ =  fmt.Fprintf(os.Stderr, "WARNING: Failed to load module: %s\n", err)
			continue
		}
		e.modules = append(e.modules, module)
	}

	return nil
}

type ModuleInfo struct {
	Name string
	Path string
	Definition *Block
	Blocks Blocks
}

// takes in a module "x" {} block and loads resources etc. into e.moduleBlocks - additionally returns variables to add to ["module.x.*"] variables
func (e *Evaluator) loadModule(block *Block) (*ModuleInfo, error) {

	if block.Label() == "" {
		return nil, fmt.Errorf("module without label at %s", block.Range())
	}

	var source string
	attrs, _ := block.hclBlock.Body.JustAttributes()
	for _, attr := range attrs {
		if attr.Name == "source" {
			sourceVal, _ := attr.Expr.Value(e.ctx)
			if sourceVal.Type() == cty.String {
				source = sourceVal.AsString()
			}
		}
	}

	if source == "" {
		return nil, fmt.Errorf("could not read module source attribute at %s", block.Range().String())
	}

	var modulePath string

	if e.moduleMetadata != nil {
		// if we have module metadata we can parse all the modules as they'll be cached locally!
		for _, module := range e.moduleMetadata.Modules {
			if module.Key == block.Label() || module.Source == source {
				modulePath = filepath.Clean(filepath.Join(e.moduleBasePath, module.Dir))
				break
			}
		}
	}

	if modulePath == "" {
		// if we have no metadata, we can only support modules available on the local filesystem
		// users wanting this feature should run a `terraform init` before running tfsec to cache all modules locally
		if !strings.HasPrefix(source, "./") && !strings.HasPrefix(source, "../") {
			if e.moduleMetadata == nil {
				return nil, fmt.Errorf("no mechanism to locate module source for %s from %s - please run `terraform init` first", block.FullName(), source)
			}else{
				return nil, fmt.Errorf("could not find module source for %s from %s", block.FullName(), source)
			}
		}

		modulePath = filepath.Join(filepath.Dir(block.Range().Filename), source)
	}

	// todo forward excluded directories?
	moduleFiles, err := LoadDirectory(modulePath)
	if err != nil {
		return  nil, err
	}

	var blocks Blocks

	for _, file := range moduleFiles {
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

	debug.Log("Found module at %s (defined at %s)", modulePath, block.Range())

	return &ModuleInfo{
		Name:   block.Label(),
		Path:   modulePath,
		Definition: block,
		Blocks: blocks,
	}, nil
}


func(e *Evaluator) evaluateModules() {

	for _, module := range e.modules {

		// TODO wrap and catch panic

		inputVars := make(map[string]cty.Value)
		for _, attr := range module.Definition.GetAttributes() {
			func() {
				defer func() {
					if err := recover(); err != nil {
						return
					}
				}()
				inputVars[attr.Name()] = attr.Value()
			}()
		}
		moduleEvaluator := NewEvaluator(module.Path, module.Blocks, inputVars, e.moduleMetadata)
		moduleEvaluator.SetModuleBasePath(e.moduleBasePath)
		_, _ = moduleEvaluator.EvaluateAll()

		// export module outputs
		moduleMapRaw := e.ctx.Variables["module"]
		if moduleMapRaw == cty.NilVal {
			moduleMapRaw = cty.ObjectVal(make(map[string]cty.Value))
		}
		moduleMap := moduleMapRaw.AsValueMap()
		if moduleMap == nil {
			moduleMap = make(map[string]cty.Value)
		}
		moduleMap[module.Name] = moduleEvaluator.ExportOutputs()
		e.ctx.Variables["module"] = cty.ObjectVal(moduleMap)
	}
}

// export module outputs to a parent context
func (e *Evaluator) ExportOutputs() cty.Value {
	return e.ctx.Variables["output"]
}

func (e *Evaluator) EvaluateAll() (Blocks, error) {

	debug.Log("Loading modules...")
	if err := e.loadModules(); err != nil {
		return nil, err
	}

	debug.Log("Beginning evaluation...")

	var lastContext hcl.EvalContext

	for i := 0; i < maxContextIterations; i++ {

		e.evaluateStep(i)

		// if ctx matches the last evaluation, we can bail, nothing left to resolve
		if reflect.DeepEqual(lastContext.Variables, e.ctx.Variables) {
			break
		}

		lastContext.Variables = make(map[string]cty.Value)
		for k, v := range e.ctx.Variables {
			lastContext.Variables[k] = v
		}
	}

	return e.blocks, nil
}

// returns true if all evaluations were successful
func (e *Evaluator) getValuesByBlockType(blockType string) cty.Value {

	blocksOfType := e.blocks.OfType(blockType)
	values := make(map[string]cty.Value)

	for _, block := range blocksOfType {

		switch block.Type() {
		case "variable": // variables are special in that their value comes from the "default" attribute

			if block.Label() == "" {
				continue
			}

			attributes, _ := block.hclBlock.Body.JustAttributes()
			if attributes == nil {
				continue
			}

			if override, exists := e.inputVars[block.Label()]; exists {
				values[block.Label()] = override
			} else if def, exists := attributes["default"]; exists {
				values[block.Label()], _ = def.Expr.Value(e.ctx)
			}
		case "output":

			if block.Label() == "" {
				continue
			}

			attributes, _ := block.hclBlock.Body.JustAttributes()
			if attributes == nil {
				continue
			}

			if def, exists := attributes["value"]; exists {
				func() {
					defer func(){
						_ = recover()
					}()
					values[block.Label()], _ = def.Expr.Value(e.ctx)
				}()
			}

		case "locals":
			for key, val := range e.readValues(block.hclBlock).AsValueMap() {
				values[key] = val
			}
		case "provider", "module":
			if block.Label() == "" {
				continue
			}
			values[block.Label()] = e.readValues(block.hclBlock)
		case "resource", "data":

			if len(block.hclBlock.Labels) < 2 {
				continue
			}

			blockMap, ok := values[block.hclBlock.Labels[0]]
			if !ok {
				values[block.hclBlock.Labels[0]] = cty.ObjectVal(make(map[string]cty.Value))
				blockMap = values[block.hclBlock.Labels[0]]
			}

			valueMap := blockMap.AsValueMap()
			if valueMap == nil {
				valueMap = make(map[string]cty.Value)
			}

			valueMap[block.hclBlock.Labels[1]] = e.readValues(block.hclBlock)
			values[block.hclBlock.Labels[0]] = cty.ObjectVal(valueMap)
		}

	}

	return cty.ObjectVal(values)

}

// returns true if all evaluations were successful
func (e *Evaluator) readValues(block *hcl.Block) cty.Value {

	values := make(map[string]cty.Value)

	attributes, diagnostics := block.Body.JustAttributes()
	if diagnostics != nil && diagnostics.HasErrors() {
		return cty.NilVal
	}

	for _, attribute := range attributes {
		func() {
			defer func(){
				if err := recover(); err != nil {
					return
				}
			}()
			val, _ := attribute.Expr.Value(e.ctx)
			values[attribute.Name] = val
		}()
	}

	return cty.ObjectVal(values)
}
