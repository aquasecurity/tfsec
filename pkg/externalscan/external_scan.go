package externalscan

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/aquasecurity/tfsec/pkg/result"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/parser"
	_ "github.com/aquasecurity/tfsec/internal/app/tfsec/rules"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
)

type ExternalScanner struct {
	paths           []string
	internalOptions []scanner.Option
}

func NewExternalScanner(options ...Option) *ExternalScanner {
	external := &ExternalScanner{}
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
	return nil
}

func (t *ExternalScanner) Scan() ([]result.Result, error) {

	projectBlocks := make(map[string]block.Blocks)

	dirs, err := findTFRootModules(t.paths)
	if err != nil {
		return nil, err
	}

	for _, dir := range dirs {
		blocks, err := parser.New(dir).ParseDirectory()
		if err != nil {
			return nil, err
		}
		projectBlocks[dir] = blocks
	}

	var results []result.Result
	internal := scanner.New(t.internalOptions...)
	for _, blockset := range projectBlocks {
		projectResults := internal.Scan(blockset)
		results = append(results, projectResults...)
	}

	return results, nil
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
