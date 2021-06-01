package externalscan

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	_ "github.com/tfsec/tfsec/internal/app/tfsec/checks"
	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

type ExternalScanner struct {
	files []string
}

func NewExternalScanner() *ExternalScanner {
	return &ExternalScanner{}
}

func (t *ExternalScanner) AddFile(file string) error {
	abs, err := filepath.Abs(file)
	if err != nil {
		return err
	}
	t.files = append(t.files, abs)
	return nil
}

func (t *ExternalScanner) Scan() ([]scanner.Result, error) {

	projectBlocks := make(map[string]parser.Blocks)

	dirs := findTFRootModules(t.files)

	for _, dir := range dirs {
		blocks, err := parser.New(dir, "").ParseDirectory()
		if err != nil {
			return nil, err
		}
		projectBlocks[dir] = blocks
	}

	var results []scanner.Result

	for _, blockset := range projectBlocks {
		projectResults := scanner.New().Scan(blockset, nil)
		results = append(results, projectResults...)
	}

	return results, nil
}

func findTFRootModules(files []string) []string {

	var output []string

	if len(files) == 0 {
		return nil
	}

	dirMap := make(map[string]bool)
	for _, file := range files {
		dir := path.Dir(file)
		dirMap[dir] = true
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

	return output
}
