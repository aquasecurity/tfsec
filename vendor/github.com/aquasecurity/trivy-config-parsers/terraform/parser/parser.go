package parser

import (
    "fmt"
    "github.com/aquasecurity/trivy-config-parsers/terraform/context"
    "github.com/zclconf/go-cty/cty"
    "io/fs"
    "io/ioutil"
    "os"
    "path/filepath"
    "strings"
    "time"

    "github.com/aquasecurity/trivy-config-parsers/terraform"
    "github.com/hashicorp/hcl/v2"
    "github.com/hashicorp/hcl/v2/hclparse"
)

type sourceFile struct {
    file *hcl.File
    path string
}

type Parser interface {
    ParseFile(path string) error
    ParseDirectory(path string) error
    EvaluateAll() (terraform.Modules, cty.Value, error)
    Metrics() Metrics
    NewModuleParser(modulePath string, moduleName string, moduleBlock *terraform.Block) Parser
}

type Metrics struct {
    Timings struct {
        DiskIODuration time.Duration
        ParseDuration  time.Duration
    }
    Counts struct {
        Blocks  int
        Modules int
        Files   int
    }
}

// Parser is a tool for parsing terraform templates at a given file system location
type parser struct {
    projectRoot    string
    moduleName     string
    modulePath     string
    moduleBlock    *terraform.Block
    files          []sourceFile
    excludePaths   []string
    tfvarsPaths    []string
    stopOnHCLError bool
    stopOnFirstTf  bool
    workspaceName  string
    skipDownloaded bool
    underlying     *hclparse.Parser
    children       []Parser
    metrics        Metrics
    options        []Option
}

// New creates a new Parser
func New(options ...Option) Parser {
    p := &parser{
        stopOnFirstTf: true,
        workspaceName: "default",
        underlying:    hclparse.NewParser(),
        options:       options,
        moduleName:    "root",
    }

    for _, option := range options {
        option(p)
    }

    return p
}

func (p *parser) NewModuleParser(modulePath string, moduleName string, moduleBlock *terraform.Block) Parser {
    mp := New(p.options...)
    mp.(*parser).modulePath = modulePath
    mp.(*parser).moduleBlock = moduleBlock
    mp.(*parser).moduleName = moduleName
    mp.(*parser).projectRoot = p.projectRoot
    p.children = append(p.children, mp)
    return mp
}

func (p *parser) Metrics() Metrics {
    total := p.metrics
    for _, child := range p.children {
        metrics := child.Metrics()
        total.Counts.Files += metrics.Counts.Files
        total.Counts.Blocks += metrics.Counts.Blocks
        total.Timings.ParseDuration += metrics.Timings.ParseDuration
        total.Timings.DiskIODuration += metrics.Timings.DiskIODuration
        // NOTE: we don't add module count - this has already propagated to the top level
    }
    return total
}

func (p *parser) ParseFile(fullPath string) error {

    if dir := filepath.Dir(fullPath); p.projectRoot == "" || len(dir) < len(p.projectRoot) {
        p.projectRoot = dir
        p.modulePath = dir
    }

    isJSON := strings.HasSuffix(fullPath, ".tf.json")
    isHCL := strings.HasSuffix(fullPath, ".tf")
    if !isJSON && !isHCL {
        return nil
    }

    diskStart := time.Now()
    data, err := ioutil.ReadFile(fullPath)
    if err != nil {
        return err
    }
    p.metrics.Timings.DiskIODuration += time.Since(diskStart)
    start := time.Now()
    var file *hcl.File
    var diag hcl.Diagnostics
    if isHCL {
        file, diag = p.underlying.ParseHCL(data, fullPath)
    } else {
        file, diag = p.underlying.ParseJSON(data, fullPath)
    }
    if diag != nil && diag.HasErrors() {
        return diag
    }
    p.files = append(p.files, sourceFile{
        file: file,
        path: fullPath,
    })
    p.metrics.Counts.Files++
    p.metrics.Timings.ParseDuration += time.Since(start)
    return nil
}

// ParseDirectory parses all terraform files within a given directory
func (p *parser) ParseDirectory(fullPath string) error {

    if p.projectRoot == "" {
        p.projectRoot = fullPath
        p.modulePath = fullPath
    }

    ////debug.Log("Finding Terraform subdirectories...")
    //diskTimer := metrics.Timer("timings", "disk i/o")
    //diskTimer.Start()
    subdirectories, err := p.getSubdirectories(fullPath)
    if err != nil {
        return err
    }
    //diskTimer.Stop()

    for _, dir := range subdirectories {
        fileInfos, err := ioutil.ReadDir(dir)
        if err != nil {
            return err
        }

        for _, info := range fileInfos {
            if info.IsDir() {
                continue
            }
            if err := p.ParseFile(filepath.Join(dir, info.Name())); err != nil {
                if p.stopOnHCLError {
                    return err
                }
                continue
            }
        }
    }

    return nil
}

func (p *parser) EvaluateAll() (terraform.Modules, cty.Value, error) {

    if len(p.files) == 0 {
        return nil, cty.NilVal, nil
    }

    blocks, ignores, err := p.readBlocks(p.files)
    if err != nil {
        return nil, cty.NilVal, err
    }

    p.metrics.Counts.Blocks = len(blocks)

    var inputVars map[string]cty.Value
    if p.moduleBlock != nil {
        inputVars = p.moduleBlock.Values().AsValueMap()
    } else {
        inputVars, err = loadTFVars(p.tfvarsPaths)
        if err != nil {
            return nil, cty.NilVal, err
        }
    }

    var modulesMetadata *modulesMetadata
    if p.skipDownloaded {
        //debug.Log("Skipping module metadata loading, --exclude-downloaded-modules passed")
    } else {
        //debug.Log("Loading module metadata...")
        modulesMetadata, _ = loadModuleMetadata(p.projectRoot)
        // TODO: report error and continue?
    }

    workingDir, err := os.Getwd()
    if err != nil {
        return nil, cty.NilVal, err
    }
    evaluator := newEvaluator(
        p,
        p.projectRoot,
        p.modulePath,
        workingDir,
        p.moduleName,
        blocks,
        inputVars,
        modulesMetadata,
        p.workspaceName,
        ignores,
    )
    modules, parseDuration := evaluator.EvaluateAll()
    p.metrics.Counts.Modules = len(modules)
    p.metrics.Timings.ParseDuration = parseDuration
    return modules, evaluator.exportOutputs(), nil
}

func (p *parser) readBlocks(files []sourceFile) (terraform.Blocks, terraform.Ignores, error) {
    var blocks terraform.Blocks
    var ignores terraform.Ignores
    moduleCtx := context.NewContext(&hcl.EvalContext{}, nil)
    for _, file := range files {
        fileBlocks, fileIgnores, err := loadBlocksFromFile(file)
        if err != nil {
            if p.stopOnHCLError {
                return nil, nil, err
            }
            _, _ = fmt.Fprintf(os.Stderr, "WARNING: HCL error: %s\n", err)
            continue
        }
        for _, fileBlock := range fileBlocks {
            blocks = append(blocks, terraform.NewBlock(fileBlock, moduleCtx, p.moduleBlock, nil))
        }
        ignores = append(ignores, fileIgnores...)
    }

    sortBlocksByHierarchy(blocks)
    return blocks, ignores, nil
}

func (p *parser) getSubdirectories(path string) ([]string, error) {

    if p.skipDownloaded && filepath.Base(path) == ".terraform" {
        return nil, nil
    }

    entries, err := ioutil.ReadDir(path)
    if err != nil {
        return nil, err
    }
    entries = p.removeExcluded(path, entries)
    var results []string
    for _, entry := range entries {

        if !entry.IsDir() && (filepath.Ext(entry.Name()) == ".tf" || strings.HasSuffix(entry.Name(), ".tf.json")) {
            //debug.Log("Found qualifying subdirectory containing .tf files: %s", path)
            results = append(results, path)
            if p.stopOnFirstTf {
                return results, nil
            }
            break
        }
    }
    for _, entry := range entries {
        if entry.IsDir() {
            dirs, err := p.getSubdirectories(filepath.Join(path, entry.Name()))
            if err != nil {
                return nil, err
            }
            if p.stopOnFirstTf && len(dirs) > 0 {
                return dirs[:1], nil
            }
            results = append(results, dirs...)
        }
    }
    return results, nil
}

func (p *parser) removeExcluded(path string, entries []fs.FileInfo) (valid []fs.FileInfo) {
    if len(p.excludePaths) == 0 {
        return entries
    }
    for _, entry := range entries {
        var remove bool
        fullPath := filepath.Join(path, entry.Name())
        for _, excludePath := range p.excludePaths {
            if fullPath == excludePath {
                remove = true
            }
        }
        if !remove {
            valid = append(valid, entry)
        }
    }
    return valid
}
