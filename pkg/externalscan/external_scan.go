package externalscan

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	_ "github.com/tfsec/tfsec/internal/app/tfsec/checks"
	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

type options []scanner.ScannerOption

type option func(*options)

func WithIncludedPassed() option {
	return func(opts *options) {
		*opts = append(*opts, scanner.IncludePassed)
	}
}

func WithIncludedIgnored() option {
	return func(opts *options) {
		*opts = append(*opts, scanner.IncludeIgnored)
	}
}

type ExternalScanner struct {
	paths []string
}


func NewExternalScanner() *ExternalScanner {
	return &ExternalScanner{}
}

func (t *ExternalScanner) AddPath(path string) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	t.paths = append(t.paths, abs)
	return nil
}

func (t *ExternalScanner) Scan( opts...option) ([]scanner.Result, error) {

	scannerOptions := new(options)
	for _, opt := range opts {
		opt(scannerOptions)
	}

	projectBlocks := make(map[string]parser.Blocks)

	dirs, err := findTFRootModules(t.paths)
	if err != nil {
		return nil, err
	}

	for _, dir := range dirs {
		blocks, err := parser.New(dir, "").ParseDirectory()
		if err != nil {
			return nil, err
		}
		projectBlocks[dir] = blocks
	}

	var results []scanner.Result

	for _, blockset := range projectBlocks {
		projectResults := scanner.New().Scan(blockset, nil, *scannerOptions...)
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
