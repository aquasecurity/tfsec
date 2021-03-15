package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/tfsec/tfsec/internal/app/tfsec/config"

	"github.com/tfsec/tfsec/internal/app/tfsec/custom"

	"github.com/tfsec/tfsec/internal/app/tfsec/debug"

	"github.com/tfsec/tfsec/internal/app/tfsec/formatters"

	"github.com/liamg/tml"

	"github.com/spf13/cobra"

	_ "github.com/tfsec/tfsec/internal/app/tfsec/checks"
	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
	"github.com/tfsec/tfsec/version"
)

var showVersion = false
var disableColours = false
var format string
var softFail = false
var excludedChecks string
var tfvarsPath string
var outputFlag string
var customCheckDir string
var configFile string
var tfsecConfig = &config.Config{}
var conciseOutput = false
var excludeDownloaded = false
var detailedExitCode = false
var includePassed = false
var allDirs = false

func init() {
	rootCmd.Flags().BoolVar(&disableColours, "no-colour", disableColours, "Disable coloured output")
	rootCmd.Flags().BoolVar(&disableColours, "no-color", disableColours, "Disable colored output (American style!)")
	rootCmd.Flags().BoolVarP(&showVersion, "version", "v", showVersion, "Show version information and exit")
	rootCmd.Flags().StringVarP(&format, "format", "f", format, "Select output format: default, json, csv, checkstyle, junit, sarif")
	rootCmd.Flags().StringVarP(&excludedChecks, "exclude", "e", excludedChecks, "Provide checks via , without space to exclude from run.")
	rootCmd.Flags().BoolVarP(&softFail, "soft-fail", "s", softFail, "Runs checks but suppresses error code")
	rootCmd.Flags().StringVar(&tfvarsPath, "tfvars-file", tfvarsPath, "Path to .tfvars file")
	rootCmd.Flags().StringVar(&outputFlag, "out", outputFlag, "Set output file")
	rootCmd.Flags().StringVar(&customCheckDir, "custom-check-dir", customCheckDir, "Explicitly the custom checks dir location")
	rootCmd.Flags().StringVar(&configFile, "config-file", configFile, "Config file to use during run")
	rootCmd.Flags().BoolVar(&debug.Enabled, "verbose", debug.Enabled, "Enable verbose logging")
	rootCmd.Flags().BoolVar(&conciseOutput, "concise-output", conciseOutput, "Reduce the amount of output and no statistics")
	rootCmd.Flags().BoolVar(&excludeDownloaded, "exclude-downloaded-modules", excludeDownloaded, "Remove results for downloaded modules in .terraform folder")
	rootCmd.Flags().BoolVar(&detailedExitCode, "detailed-exit-code", detailedExitCode, "Produce more detailed exit status codes.")
	rootCmd.Flags().BoolVar(&includePassed, "include-passed", includePassed, "Include passed checks in the result output")
	rootCmd.Flags().BoolVar(&allDirs, "force-all-dirs", allDirs, "Don't search for tf files, include everything below provided directory.")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

var rootCmd = &cobra.Command{
	Use:   "tfsec [directory]",
	Short: "tfsec is a terraform security scanner",
	Long:  `tfsec is a simple tool to detect potential security vulnerabilities in your terraformed infrastructure.`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {

		// disable colour if running on windows - colour formatting doesn't work
		if disableColours || runtime.GOOS == "windows" {
			debug.Log("Disabled formatting.")
			tml.DisableFormatting()
		}

		if showVersion {
			fmt.Println(version.Version)
			os.Exit(0)
		}
	},
	Run: func(cmd *cobra.Command, args []string) {

		var dir string
		var err error
		var excludedChecksList []string
		var outputFile *os.File

		if len(args) == 1 {
			dir, err = filepath.Abs(args[0])
		} else {
			dir, err = os.Getwd()
		}
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		tfsecDir := fmt.Sprintf("%s/.tfsec", dir)

		if len(configFile) > 0 {
			tfsecConfig = loadConfigFile(configFile)
		} else {
			jsonConfigFile := fmt.Sprintf("%s/%s", tfsecDir, "config.json")
			yamlConfigFile := fmt.Sprintf("%s/%s", tfsecDir, "config.yml")
			if _, err = os.Stat(jsonConfigFile); err == nil {
				tfsecConfig = loadConfigFile(jsonConfigFile)
			} else if _, err = os.Stat(yamlConfigFile); err == nil {
				tfsecConfig = loadConfigFile(yamlConfigFile)
			} else {
				tfsecConfig = &config.Config{}
			}
		}

		debug.Log("Loading custom checks...")
		if len(customCheckDir) == 0 {
			debug.Log("Using the default custom check folder")
			customCheckDir = tfsecDir
		}
		debug.Log("custom check directory set to %s", customCheckDir)
		err = custom.Load(customCheckDir)
		if err != nil {
			fmt.Fprint(os.Stderr, fmt.Sprintf("There were errors while processing custom check files. %s", err))
			os.Exit(1)
		}
		debug.Log("Custom checks loaded")

		if len(excludedChecks) > 0 {
			excludedChecksList = strings.Split(excludedChecks, ",")
		}

		if outputFlag != "" {
			f, err := os.OpenFile(filepath.Clean(outputFlag), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
			defer func() { _ = f.Close() }()
			outputFile = f
		} else {
			outputFile = os.Stdout
		}

		formatter, err := getFormatter()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		if tfvarsPath != "" {
			tfvarsPath, err = filepath.Abs(tfvarsPath)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
		}

		debug.Log("Starting parser...")
		blocks, err := parser.New(dir, tfvarsPath, getParserOptions()...).ParseDirectory()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		debug.Log("Starting scanner...")
		results := scanner.New().Scan(blocks, mergeWithoutDuplicates(excludedChecksList, tfsecConfig.ExcludedChecks), getScannerOptions()...)
		results = updateResultSeverity(results)
		results = removeDuplicatesAndUnwanted(results)

		if err := formatter(outputFile, results, dir, getFormatterOptions()...); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		// Soft fail always takes precedence. If set, only execution errors
		// produce a failure exit code (1).
		if softFail {
			os.Exit(0)
		}

		if detailedExitCode {
			os.Exit(getDetailedExitCode(results))
		}

		// If all failed checks are of INFO severity, then produce a success
		// exit code (0).
		if allInfo(results) {
			os.Exit(0)
		}

		os.Exit(1)
	},
}

func getParserOptions() []parser.ParserOption {
	var opts []parser.ParserOption
	if allDirs {
		opts = append(opts, parser.DontSearchTfFiles)
	}
	return opts
}

func getDetailedExitCode(results []scanner.Result) int {
	// If there are no failed checks, then produce a success exit code (0).
	if len(results) == 0 || len(results) == countPassedResults(results) {
		return 0
	}

	// If there are some failed checks but they are all of INFO severity, then
	// produce a special failure exit code (2).
	if allInfo(results) {
		return 2
	}

	// If there is any failed check of ERROR or WARNING severity, then
	// produce the regular failure exit code (1).
	return 1
}

func removeDuplicatesAndUnwanted(results []scanner.Result) []scanner.Result {
	reduction := map[scanner.Result]bool{}

	for _, result := range results {
		reduction[result] = true
	}

	var returnVal []scanner.Result
	for r, _ := range reduction {
		if excludeDownloaded && strings.Contains(r.Range.Filename, "/.terraform") {
			continue
		}
		returnVal = append(returnVal, r)
	}
	return returnVal
}

func getFormatterOptions() []formatters.FormatterOption {
	var options []formatters.FormatterOption
	if conciseOutput {
		options = append(options, formatters.ConciseOutput)
	}
	if includePassed {
		options = append(options, formatters.IncludePassed)
	}
	return options
}

func getScannerOptions() []scanner.ScannerOption {
	var options []scanner.ScannerOption
	if includePassed {
		options = append(options, scanner.IncludePassed)
	}
	return options
}

func mergeWithoutDuplicates(left, right []string) []string {
	all := append(left, right...)
	var set = map[string]bool{}
	for _, x := range all {
		set[x] = true
	}
	var result []string
	for x, _ := range set {
		result = append(result, x)
	}

	return result
}

func allInfo(results []scanner.Result) bool {
	for _, result := range results {
		if result.Severity != scanner.SeverityInfo && !result.Passed {
			return false
		}
	}
	return true
}

func updateResultSeverity(results []scanner.Result) []scanner.Result {
	overrides := tfsecConfig.SeverityOverrides

	if len(overrides) == 0 {
		return results
	}

	var overriddenResults []scanner.Result
	for _, result := range results {
		for code, severity := range overrides {
			if result.RuleID == scanner.RuleCode(code) {
				result.OverrideSeverity(severity)
			}
		}
		overriddenResults = append(overriddenResults, result)
	}

	return overriddenResults
}

func getFormatter() (formatters.Formatter, error) {
	switch strings.ToLower(format) {
	case "", "default":
		return formatters.FormatDefault, nil
	case "json":
		return formatters.FormatJSON, nil
	case "csv":
		return formatters.FormatCSV, nil
	case "checkstyle":
		return formatters.FormatCheckStyle, nil
	case "junit":
		return formatters.FormatJUnit, nil
	case "text":
		return formatters.FormatText, nil
	case "sarif":
		return formatters.FormatSarif, nil
	default:
		return nil, fmt.Errorf("invalid format specified: '%s'", format)
	}
}

func loadConfigFile(configFilePath string) *config.Config {
	debug.Log("loading config file %s", configFilePath)
	config, err := config.LoadConfig(configFilePath)
	if err != nil {
		fmt.Fprint(os.Stderr, fmt.Sprintf("Failed to load the config file. %s", err))
		os.Exit(1)
	}
	debug.Log("loaded config file")
	return config
}

func countPassedResults(results []scanner.Result) int {
	passed := 0

	for _, result := range results {
		if result.Passed {
			passed++
		}
	}

	return passed
}
