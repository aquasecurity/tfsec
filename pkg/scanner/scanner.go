package scanner

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aquasecurity/tfsec/internal/pkg/custom"

	"github.com/aquasecurity/tfsec/internal/pkg/config"

	"github.com/aquasecurity/defsec/rules"

	"github.com/aquasecurity/tfsec/internal/pkg/executor"
	"github.com/aquasecurity/trivy-config-parsers/terraform/parser"
)

type Scanner struct {
	parserOpt      []parser.Option
	executorOpt    []executor.Option
	dirs           map[string]struct{}
	forceAllDirs   bool
	customCheckDir string
	configFile     string
}

type Metrics struct {
	Parser   parser.Metrics
	Executor executor.Metrics
	Timings  struct {
		Total time.Duration
	}
}

func New(options ...Option) *Scanner {
	s := &Scanner{
		dirs: make(map[string]struct{}),
	}
	for _, opt := range options {
		opt(s)
	}
	return s
}

func (s *Scanner) AddPath(path string) error {
	path, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	path = filepath.Clean(path)
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if info.IsDir() {
		s.dirs[path] = struct{}{}
	} else {
		s.dirs[filepath.Dir(path)] = struct{}{}
	}
	return nil
}

func (s *Scanner) Scan() (rules.Results, Metrics, error) {

	var metrics Metrics
	if s.configFile != "" {
		if conf, err := config.LoadConfig(s.configFile); err == nil {
			s.executorOpt = append(s.executorOpt, executor.OptionWithConfig(*conf))
		}
	}
	if s.customCheckDir != "" {
		if err := custom.Load(s.customCheckDir); err != nil {
			return nil, metrics, err
		}
	}

	// don't scan child directories that have parent directories containing tf files!
	var dirs []string
	for dir := range s.dirs {
		dirs = append(dirs, dir)
	}
	simplifiedDirs := s.removeNestedDirs(dirs)

	// find directories which directly contain tf files (and have no parent containing tf files)
	rootDirs := s.findRootModules(simplifiedDirs)

	var allResults rules.Results

	// parse all root module directories
	for _, dir := range rootDirs {

		p := parser.New(s.parserOpt...)
		e := executor.New(s.executorOpt...)

		if err := p.ParseDirectory(dir); err != nil {
			return nil, metrics, err
		}

		modules, _, err := p.EvaluateAll()
		if err != nil {
			return nil, metrics, err
		}

		parserMetrics := p.Metrics()
		metrics.Parser.Counts.Blocks += parserMetrics.Counts.Blocks
		metrics.Parser.Counts.Modules += parserMetrics.Counts.Modules
		metrics.Parser.Counts.Files += parserMetrics.Counts.Files
		metrics.Parser.Timings.DiskIODuration += parserMetrics.Timings.DiskIODuration
		metrics.Parser.Timings.ParseDuration += parserMetrics.Timings.ParseDuration

		results, execMetrics, err := e.Execute(modules)
		if err != nil {
			return nil, metrics, err
		}

		metrics.Executor.Counts.Passed += execMetrics.Counts.Passed
		metrics.Executor.Counts.Failed += execMetrics.Counts.Failed
		metrics.Executor.Counts.Ignored += execMetrics.Counts.Ignored
		metrics.Executor.Counts.Excluded += execMetrics.Counts.Excluded
		metrics.Executor.Counts.Critical += execMetrics.Counts.Critical
		metrics.Executor.Counts.High += execMetrics.Counts.High
		metrics.Executor.Counts.Medium += execMetrics.Counts.Medium
		metrics.Executor.Counts.Low += execMetrics.Counts.Low
		metrics.Executor.Timings.Adaptation += execMetrics.Timings.Adaptation
		metrics.Executor.Timings.RunningChecks += execMetrics.Timings.RunningChecks

		allResults = append(allResults, results...)
	}

	return allResults, metrics, nil
}

func (s *Scanner) removeNestedDirs(dirs []string) []string {
	var clean []string
	for _, dirA := range dirs {
		dirOK := true
		for _, dirB := range dirs {
			if dirA == dirB {
				continue
			}
			if str, err := filepath.Rel(dirB, dirA); err == nil && !strings.HasPrefix(str, "..") {
				dirOK = false
				break
			}
		}
		if dirOK {
			clean = append(clean, dirA)
		}
	}
	return clean
}

func (s *Scanner) findRootModules(dirs []string) []string {

	var roots []string
	var others []string

	for _, dir := range dirs {
		if isRootModule(dir) {
			roots = append(roots, dir)
			continue
		}

		// if this isn't a root module, look at directories inside it
		files, err := ioutil.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, file := range files {
			if file.IsDir() {
				others = append(others, filepath.Join(dir, file.Name()))
			}
		}
	}

	if (len(roots) == 0 || s.forceAllDirs) && len(others) > 0 {
		roots = append(roots, s.findRootModules(others)...)
	}

	return s.removeNestedDirs(roots)
}

func isRootModule(dir string) bool {
	files, err := ioutil.ReadDir(dir)
	if err != nil {
		return false
	}
	for _, file := range files {
		if strings.HasSuffix(file.Name(), ".tf") || strings.HasSuffix(file.Name(), ".tf.json") {
			return true
		}
	}
	return false
}
