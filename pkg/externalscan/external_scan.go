package externalscan

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/custom"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/parser"
	_ "github.com/aquasecurity/tfsec/internal/app/tfsec/rules"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

type ExternalScanner struct {
	paths                     []string
	internalOptions           []scanner.Option
	processedCustomCheckFiles map[string]bool
}

const customChecksDir = ".tfsec"

func NewExternalScanner(options ...Option) *ExternalScanner {
	external := &ExternalScanner{
		processedCustomCheckFiles: make(map[string]bool),
	}
	for _, option := range options {
		option(external)
	}
	return external
}

func (t *ExternalScanner) AddPath(path string) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	t.paths = append(t.paths, abs)

	customCheckDir := filepath.Join(filepath.Dir(path), customChecksDir)

	if _, ok := t.processedCustomCheckFiles[customCheckDir]; ok {
		return nil

	}
	t.processedCustomCheckFiles[customCheckDir] = true
	return custom.Load(customCheckDir)
}

func (t *ExternalScanner) Scan() ([]rules.FlatResult, error) {

	projectModules := make(map[string][]block.Module)

	dirs, err := findTFRootModules(t.paths)
	if err != nil {
		return nil, err
	}

	for _, dir := range dirs {
		modules, err := parser.New(dir).ParseDirectory()
		if err != nil {
			return nil, err
		}
		projectModules[dir] = modules
	}

	var results rules.Results
	internal := scanner.New(t.internalOptions...)
	for _, modules := range projectModules {
		projectResults, _ := internal.Scan(modules)
		results = append(results, projectResults...)
	}

	return results.Flatten(), nil
}

func findTFRootModules(paths []string) ([]string, error) {

	var output []string

	if len(paths) == 0 {
		return nil, fmt.Errorf("no files to scan")
	}

	dirMap := make(map[string]bool)
	for _, path := range paths {
		stat, err := os.Stat(path)
		if err != nil {
			return nil, err
		}
		if stat.IsDir() {
			dirMap[path] = true
		} else {
			dirMap[filepath.Dir(path)] = true
		}

	}

	var dirs []string
	for dir := range dirMap {
		dirs = append(dirs, dir)
	}

	sort.Strings(dirs)

	previous := dirs[0]
	output = append(output, previous)

	for i := 1; i < len(dirs); i++ {
		if !strings.HasPrefix(dirs[i], fmt.Sprintf("%s%c", previous, os.PathSeparator)) {
			output = append(output, dirs[i])
		}
		previous = dirs[i]
	}

	return output, nil
}
