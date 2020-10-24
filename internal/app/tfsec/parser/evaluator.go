package parser

import (
	"reflect"

	"github.com/tfsec/tfsec/internal/app/tfsec/timer"

	"github.com/hashicorp/hcl/v2"
	"github.com/tfsec/tfsec/internal/app/tfsec/debug"
	"github.com/zclconf/go-cty/cty"
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

func NewEvaluator(path string, blocks Blocks, inputVars map[string]cty.Value, moduleMetadata *ModulesMetadata, modules []*ModuleInfo) *Evaluator {

	ctx := &hcl.EvalContext{
		Variables: make(map[string]cty.Value),
		Functions: Functions(path),
	}

	// attach context to blocks
	for _, block := range blocks {
		block.ctx = ctx
	}

	return &Evaluator{
		path:           path,
		moduleBasePath: path,
		ctx:            ctx,
		blocks:         blocks,
		inputVars:      inputVars,
		moduleMetadata: moduleMetadata,
		modules:        modules,
	}
}

func (e *Evaluator) SetModuleBasePath(path string) {
	e.moduleBasePath = path
}

func (e *Evaluator) evaluateStep(i int) {

	evalTime := timer.Start(timer.Evaluation)
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

	evalTime.Stop()

	e.evaluateModules()
}

func (e *Evaluator) evaluateModules() {

	for _, module := range e.modules {

		evalTime := timer.Start(timer.Evaluation)
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
		evalTime.Stop()

		childModules := LoadModules(module.Blocks, e.moduleBasePath, e.moduleMetadata)
		moduleEvaluator := NewEvaluator(module.Path, module.Blocks, inputVars, e.moduleMetadata, childModules)
		moduleEvaluator.SetModuleBasePath(e.moduleBasePath)
		_, _ = moduleEvaluator.EvaluateAll()

		evalTime = timer.Start(timer.Evaluation)
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
		evalTime.Stop()
	}
}

// export module outputs to a parent context
func (e *Evaluator) ExportOutputs() cty.Value {
	return e.ctx.Variables["output"]
}

func (e *Evaluator) EvaluateAll() (Blocks, error) {

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

	var allBlocks Blocks
	allBlocks = append(allBlocks, e.blocks...)
	for _, module := range e.modules {
		allBlocks = append(allBlocks, module.Blocks...)
	}

	return allBlocks, nil
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
					defer func() {
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
			defer func() {
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
