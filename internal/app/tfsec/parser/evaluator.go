package parser

import (
	"fmt"
	"reflect"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/metrics"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/debug"
	"github.com/hashicorp/hcl/v2"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/gocty"
)

const maxContextIterations = 32

type visitedModule struct {
	name                string
	path                string
	definitionReference string
}

type Evaluator struct {
	ctx             *hcl.EvalContext
	blocks          block.Blocks
	modules         []*ModuleInfo
	visitedModules  []*visitedModule
	inputVars       map[string]cty.Value
	moduleMetadata  *ModulesMetadata
	projectRootPath string // root of the current scan
	stopOnHCLError  bool
	modulePath      string
}

func NewEvaluator(
	projectRootPath string,
	modulePath string,
	blocks block.Blocks,
	inputVars map[string]cty.Value,
	moduleMetadata *ModulesMetadata,
	visitedModules []*visitedModule,
	stopOnHCLError bool,
) *Evaluator {

	ctx := &hcl.EvalContext{
		Variables: make(map[string]cty.Value),
		Functions: Functions(modulePath),
	}

	for _, b := range blocks {
		b.AttachEvalContext(ctx.NewChild())
	}

	return &Evaluator{
		modulePath:      modulePath,
		projectRootPath: projectRootPath,
		ctx:             ctx,
		blocks:          blocks,
		inputVars:       inputVars,
		moduleMetadata:  moduleMetadata,
		visitedModules:  visitedModules,
		stopOnHCLError:  stopOnHCLError,
	}
}

func (e *Evaluator) SetModuleBasePath(path string) {
	e.projectRootPath = path
}

func (e *Evaluator) evaluateStep(i int) {

	evalTime := metrics.Start(metrics.Evaluation)
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
		if visited := func(module *ModuleInfo) bool {
			for _, v := range e.visitedModules {
				if v.name == module.Name && v.path == module.Path && module.Definition.Reference().String() == v.definitionReference {
					debug.Log("Module [%s:%s:%s] has already been seen", v.name, v.path, v.definitionReference)
					return true
				}
			}
			return false
		}(module); visited {
			continue
		}

		e.visitedModules = append(e.visitedModules, &visitedModule{module.Name, module.Path, module.Definition.Reference().String()})

		evalTime := metrics.Start(metrics.Evaluation)
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

		moduleEvaluator := NewEvaluator(e.projectRootPath, module.Path, module.Blocks, inputVars, e.moduleMetadata, e.visitedModules, e.stopOnHCLError)
		e.SetModuleBasePath(e.projectRootPath)
		module.Blocks, _ = moduleEvaluator.EvaluateAll()

		evalTime = metrics.Start(metrics.Evaluation)
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

// export module outputs to a parent hclcontext
func (e *Evaluator) ExportOutputs() cty.Value {
	return e.ctx.Variables["output"]
}

func (e *Evaluator) EvaluateAll() (block.Blocks, error) {

	var lastContext hcl.EvalContext

	for i := 0; i < maxContextIterations; i++ {

		e.evaluateStep(i)

		// if ctx matches the last evaluation, we can bail, nothing left to resolve
		if reflect.DeepEqual(lastContext.Variables, e.ctx.Variables) {
			break
		}

		if len(e.ctx.Variables) != len(lastContext.Variables) {
			lastContext.Variables = make(map[string]cty.Value, len(e.ctx.Variables))
		}
		for k, v := range e.ctx.Variables {
			lastContext.Variables[k] = v
		}
	}

	debug.Log("Loading modules...")
	e.modules = e.loadModules(true)

	// expand out resources and modules via count
	e.blocks = e.expandBlockCounts(e.blocks)

	for i := 0; i < maxContextIterations; i++ {

		e.evaluateStep(i)

		// if ctx matches the last evaluation, we can bail, nothing left to resolve
		if reflect.DeepEqual(lastContext.Variables, e.ctx.Variables) {
			break
		}

		if len(e.ctx.Variables) != len(lastContext.Variables) {
			lastContext.Variables = make(map[string]cty.Value, len(e.ctx.Variables))
		}
		for k, v := range e.ctx.Variables {
			lastContext.Variables[k] = v
		}
	}

	allBlocks := e.blocks
	for _, module := range e.modules {
		allBlocks = append(allBlocks, module.Blocks...)
	}

	return allBlocks, nil
}

/*
Input:
resource.aws_s3_bucket.blah -> count=3
Output:
resource.aws_s3_bucket.blah[0] -> count.index=0
resource.aws_s3_bucket.blah[1] -> count.index=1
resource.aws_s3_bucket.blah[2] -> count.index=2
*/
func (e *Evaluator) expandBlockCounts(blocks block.Blocks) block.Blocks {

	var forEachFiltered block.Blocks
	for _, block := range blocks {
		forEachAttr := block.GetAttribute("for_each")
		if forEachAttr == nil || block.IsCountExpanded() || (block.Type() != "resource" && block.Type() != "module") {
			forEachFiltered = append(forEachFiltered, block)
			continue
		}
		if !forEachAttr.Value().IsNull() && forEachAttr.Value().IsKnown() && forEachAttr.IsIterable() {
			forEachAttr.Each(func(key cty.Value, val cty.Value) {
				clone := block.Clone(key)

				ctx := clone.Context()

				e.copyVariables(block, clone)

				ctx.Variables["each"] = cty.ObjectVal(map[string]cty.Value{
					"key":   key,
					"value": val,
				})

				debug.Log("Added %s from for_each", clone.Reference())
				forEachFiltered = append(forEachFiltered, clone)
			})
		}
	}

	var countFiltered block.Blocks
	for _, block := range forEachFiltered {
		countAttr := block.GetAttribute("count")
		if countAttr == nil || block.IsCountExpanded() || (block.Type() != "resource" && block.Type() != "module") {
			countFiltered = append(countFiltered, block)
			continue
		}
		count := 1
		if !countAttr.Value().IsNull() && countAttr.Value().IsKnown() {
			if countAttr.Value().Type() == cty.Number {
				f, _ := countAttr.Value().AsBigFloat().Float64()
				count = int(f)
			}
		}

		for i := 0; i < count; i++ {
			c, _ := gocty.ToCtyValue(i, cty.Number)
			clone := block.Clone(c)
			block.TypeLabel()
			debug.Log("Added %s from count var", clone.Reference())
			countFiltered = append(countFiltered, clone)
		}
	}

	return countFiltered

}

func (e *Evaluator) copyVariables(from, to block.Block) {

	var fromBase string
	var fromRel string
	var toRel string

	switch from.Type() {
	case "resource":
		fromBase = from.TypeLabel()
		fromRel = from.NameLabel()
		toRel = to.NameLabel()
	case "module":
		fromBase = from.Type()
		fromRel = from.TypeLabel()
		toRel = to.TypeLabel()
	default:
		return
	}

	topLevelMap := e.ctx.Variables[fromBase] // s3_buckets
	if topLevelMap.Type() == cty.NilType {
		topLevelMap = cty.EmptyObjectVal
	}
	topLevelVars := topLevelMap.AsValueMap()
	if topLevelVars == nil {
		topLevelVars = map[string]cty.Value{}
	}

	relativeMap := topLevelVars[fromRel]
	if relativeMap.Type() == cty.NilType {
		relativeMap = cty.EmptyObjectVal
	}
	relativeVars := relativeMap.AsValueMap()
	if relativeVars == nil {
		relativeVars = map[string]cty.Value{}
	}
	// put back
	topLevelVars[toRel] = cty.ObjectVal(relativeVars)
	e.ctx.Variables[fromBase] = cty.ObjectVal(topLevelVars)
}

func mergeBlocks(allBlocks block.Blocks, newBlocks block.Blocks) block.Blocks {
	var merger = make(map[block.Block]bool)
	for _, b := range allBlocks {
		merger[b] = true
	}

	for _, b := range newBlocks {
		if _, ok := merger[b]; !ok {
			allBlocks = append(allBlocks, b)
		}
	}
	return allBlocks
}

func (e *Evaluator) evaluateVariable(b block.Block) (cty.Value, error) {
	if b.Label() == "" {
		return cty.NilVal, fmt.Errorf("empty label - cannot resolve")
	}

	attributes := b.Attributes()
	if attributes == nil {
		return cty.NilVal, fmt.Errorf("cannot resolve variable with no attributes")
	}

	if override, exists := e.inputVars[b.Label()]; exists {
		return override, nil
	} else if def, exists := attributes["default"]; exists {
		return def.Value(), nil
	}

	return cty.NilVal, fmt.Errorf("no value found")
}

func (e *Evaluator) evaluateOutput(b block.Block) (cty.Value, error) {

	defer func() {
		_ = recover()
	}()

	if b.Label() == "" {
		return cty.NilVal, fmt.Errorf("empty label - cannot resolve")
	}

	attributes := b.Attributes()
	if attributes == nil {
		return cty.NilVal, fmt.Errorf("cannot resolve variable with no attributes")
	}

	if def, exists := attributes["value"]; exists {
		return def.Value(), nil
	}

	return cty.NilVal, fmt.Errorf("no value found")
}

// returns true if all evaluations were successful
func (e *Evaluator) getValuesByBlockType(blockType string) cty.Value {

	blocksOfType := e.blocks.OfType(blockType)
	values := make(map[string]cty.Value)

	for _, b := range blocksOfType {

		switch b.Type() {
		case "variable": // variables are special in that their value comes from the "default" attribute
			val, err := e.evaluateVariable(b)
			if err != nil {
				continue
			}
			values[b.Label()] = val
		case "output":
			val, err := e.evaluateOutput(b)
			if err != nil {
				continue
			}
			values[b.Label()] = val
		case "locals":
			for key, val := range b.Values().AsValueMap() {
				values[key] = val
			}
		case "provider", "module":
			if b.Label() == "" {
				continue
			}
			values[b.Label()] = b.Values()
		case "resource", "data":

			if len(b.Labels()) < 2 {
				continue
			}

			blockMap, ok := values[b.Label()]
			if !ok {
				values[b.Labels()[0]] = cty.ObjectVal(make(map[string]cty.Value))
				blockMap = values[b.Labels()[0]]
			}

			valueMap := blockMap.AsValueMap()
			if valueMap == nil {
				valueMap = make(map[string]cty.Value)
			}

			valueMap[b.Labels()[1]] = b.Values()
			values[b.Labels()[0]] = cty.ObjectVal(valueMap)
		}

	}

	return cty.ObjectVal(values)

}
