package parser

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/aquasecurity/defsec/metrics"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/debug"
	"github.com/hashicorp/hcl/v2"
	"github.com/zclconf/go-cty/cty"
)

type moduleLoadError struct {
	source string
	err    error
}

func (m *moduleLoadError) Error() string {
	return fmt.Sprintf("failed to load module '%s': %s", m.source, m.err)
}

type ModuleDefinition struct {
	Name       string
	Path       string
	Definition block.Block
	Modules    []block.Module
}

// LoadModules reads all module blocks and loads the underlying modules, adding blocks to e.moduleBlocks
func (e *Evaluator) loadModules(stopOnHCLError bool) []*ModuleDefinition {

	blocks := e.blocks

	var moduleDefinitions []*ModuleDefinition

	expanded := e.expandBlocks(blocks.OfType("module"))

	var loadErrors []*moduleLoadError

	for _, moduleBlock := range expanded {
		if moduleBlock.Label() == "" {
			continue
		}
		moduleDefinition, err := e.loadModule(moduleBlock, stopOnHCLError)
		if err != nil {
			if loadErr, ok := err.(*moduleLoadError); ok {
				var found bool
				for _, fm := range loadErrors {
					if fm.source == loadErr.source {
						found = true
						break
					}
				}
				if !found {
					loadErrors = append(loadErrors, loadErr)
				}
				continue
			}
			_, _ = fmt.Fprintf(os.Stderr, "WARNING: Failed to load module: %s\n", err)
			continue
		}
		moduleDefinitions = append(moduleDefinitions, moduleDefinition)
	}

	if len(loadErrors) > 0 {
		_, _ = fmt.Fprintf(os.Stderr, "WARNING: Did you forget to 'terraform init'? The following modules failed to load:\n")
		for _, err := range loadErrors {
			_, _ = fmt.Fprintf(os.Stderr, " - %s\n", err.source)
		}
	}

	return moduleDefinitions
}

// takes in a module "x" {} block and loads resources etc. into e.moduleBlocks - additionally returns variables to add to ["module.x.*"] variables
func (e *Evaluator) loadModule(b block.Block, stopOnHCLError bool) (*ModuleDefinition, error) {

	if b.Label() == "" {
		return nil, fmt.Errorf("module without label at %s", b.Range())
	}

	evalTimer := metrics.Timer("timings", "evaluation")
	evalTimer.Start()

	var source string
	attrs := b.Attributes()
	for _, attr := range attrs {
		if attr.Name() == "source" {
			sourceVal := attr.Value()
			if sourceVal.Type() == cty.String {
				source = sourceVal.AsString()
			}
		}
	}

	evalTimer.Stop()

	if source == "" {
		return nil, fmt.Errorf("could not read module source attribute at %s", b.Range().String())
	}

	var modulePath string

	if e.moduleMetadata != nil {
		// if we have module metadata we can parse all the modules as they'll be cached locally!

		name := getModuleKeyName(b.Label(), e.moduleName)

		for _, module := range e.moduleMetadata.Modules {
			if module.Key == name {
				modulePath = filepath.Clean(filepath.Join(e.projectRootPath, module.Dir))
				break
			}
		}
	}
	if modulePath == "" {
		// if we have no metadata, we can only support modules available on the local filesystem
		// users wanting this feature should run a `terraform init` before running tfsec to cache all modules locally
		if !strings.HasPrefix(source, fmt.Sprintf(".%c", os.PathSeparator)) && !strings.HasPrefix(source, fmt.Sprintf("..%c", os.PathSeparator)) {
			return nil, &moduleLoadError{
				source: source,
				err:    errors.New("missing source code"),
			}
		}

		// combine the current calling module with relative source of the module
		modulePath = filepath.Join(e.modulePath, source)
	}

	blocks, ignores, err := getModuleBlocks(b, modulePath, e.moduleName, stopOnHCLError)
	if err != nil {
		return nil, &moduleLoadError{
			source: source,
			err:    err,
		}
	}
	debug.Log("Loaded module '%s' (requested at %s)", modulePath, b.Range())
	metrics.Counter("counts", "modules").Increment(1)

	return &ModuleDefinition{
		Name:       b.Label(),
		Path:       modulePath,
		Definition: b,
		Modules:    []block.Module{block.NewHCLModule(e.projectRootPath, modulePath, blocks, ignores)},
	}, nil
}

func getModuleBlocks(b block.Block, modulePath string, moduleName string, stopOnHCLError bool) (block.Blocks, []block.Ignore, error) {
	moduleFiles, err := LoadDirectory(modulePath, stopOnHCLError)
	if err != nil {
		return nil, nil, err
	}

	var blocks block.Blocks
	var ignores []block.Ignore

	moduleCtx := block.NewContext(&hcl.EvalContext{}, nil)
	for _, file := range moduleFiles {
		fileBlocks, fileIgnores, err := LoadBlocksFromFile(file, moduleName)
		if err != nil {
			if stopOnHCLError {
				return nil, nil, err
			}
			_, _ = fmt.Fprintf(os.Stderr, "WARNING: HCL error: %s\n", err)
			continue
		}
		if len(fileBlocks) > 0 {
			debug.Log("Added %d blocks from %s...", len(fileBlocks), fileBlocks[0].DefRange.Filename)
		}
		for _, fileBlock := range fileBlocks {
			blocks = append(blocks, block.NewHCLBlock(fileBlock, moduleCtx, b))
		}
		ignores = append(ignores, fileIgnores...)
	}
	return blocks, ignores, nil
}

func getModuleKeyName(blockName, moduleName string) (name string) {
	// regular expression for removing count and or for_each indexes
	indexRegExp := regexp.MustCompile(`\[["'0-9a-zA-Z]{0,60}\]`)

	if moduleName == "root" {
		return indexRegExp.ReplaceAllString(blockName, "")
	}
	modules := strings.Split(moduleName, ":")

	if len(modules) == 1 {
		return indexRegExp.ReplaceAllString((strings.TrimPrefix(moduleName, "module.") + "." + blockName), "")
	}
	for i, module := range modules {
		name += strings.TrimPrefix(module, "module.")
		if i != len(modules)-1 {
			name = name + "."
		}
	}
	return indexRegExp.ReplaceAllString(name, "")
}
