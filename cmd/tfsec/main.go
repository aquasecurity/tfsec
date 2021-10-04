package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"strings"

	"github.com/aquasecurity/tfsec/pkg/result"

	"github.com/aquasecurity/tfsec/pkg/severity"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/config"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/updater"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/custom"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/debug"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/formatters"

	"github.com/liamg/tml"

	"github.com/spf13/cobra"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/metrics"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/parser"
	_ "github.com/aquasecurity/tfsec/internal/app/tfsec/rules"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/version"
)

var showVersion = false
var runUpdate = false
var disableColours = false
var format string
var softFail = false
var filterResults string
var excludedRuleIDs string
var includedRuleIDs string
var tfvarsPaths []string
var outputFlag string
var customCheckDir string
var configFile string
var tfsecConfig = &config.Config{}
var conciseOutput = false
var excludeDownloaded = false
var detailedExitCode = false
var includePassed = false
var includeIgnored = false
var ignoreWarnings = false
var ignoreInfo = false
var allDirs = false
var runStatistics bool
var ignoreHCLErrors bool
var stopOnCheckError bool
var workspace string
var passingGif bool

func init() {
	rootCmd.Flags().BoolVar(&ignoreHCLErrors, "ignore-hcl-errors", ignoreHCLErrors, "Stop and report an error if an HCL parse error is encountered")
	rootCmd.Flags().BoolVar(&disableColours, "no-colour", disableColours, "Disable coloured output")
	rootCmd.Flags().BoolVar(&disableColours, "no-color", disableColours, "Disable colored output (American style!)")
	rootCmd.Flags().BoolVarP(&showVersion, "version", "v", showVersion, "Show version information and exit")
	rootCmd.Flags().BoolVar(&runUpdate, "update", runUpdate, "Update to latest version")
	rootCmd.Flags().StringVarP(&format, "format", "f", format, "Select output format: default, json, csv, checkstyle, junit, sarif")
	rootCmd.Flags().StringVarP(&excludedRuleIDs, "exclude", "e", excludedRuleIDs, "Provide comma-separated list of rule IDs to exclude from run.")
	rootCmd.Flags().StringVarP(&includedRuleIDs, "include", "i", includedRuleIDs, "Provide comma-separated list of specific rules to include in the from run.")
	rootCmd.Flags().StringVar(&filterResults, "filter-results", filterResults, "Filter results to return specific checks only (supports comma-delimited input).")
	rootCmd.Flags().BoolVarP(&softFail, "soft-fail", "s", softFail, "Runs checks but suppresses error code")
	rootCmd.Flags().StringSliceVar(&tfvarsPaths, "tfvars-file", tfvarsPaths, "Path to .tfvars file, can be used multiple times and evaluated in order of specification")
	rootCmd.Flags().StringVar(&outputFlag, "out", outputFlag, "Set output file")
	rootCmd.Flags().StringVar(&customCheckDir, "custom-check-dir", customCheckDir, "Explicitly the custom checks dir location")
	rootCmd.Flags().StringVar(&configFile, "config-file", configFile, "Config file to use during run")
	rootCmd.Flags().BoolVar(&debug.Enabled, "verbose", debug.Enabled, "Enable verbose logging")
	rootCmd.Flags().BoolVar(&conciseOutput, "concise-output", conciseOutput, "Reduce the amount of output and no statistics")
	rootCmd.Flags().BoolVar(&excludeDownloaded, "exclude-downloaded-modules", excludeDownloaded, "Remove results for downloaded modules in .terraform folder")
	rootCmd.Flags().BoolVar(&detailedExitCode, "detailed-exit-code", detailedExitCode, "Produce more detailed exit status codes.")
	rootCmd.Flags().BoolVar(&includePassed, "include-passed", includePassed, "Include passed checks in the result output")
	rootCmd.Flags().BoolVar(&includeIgnored, "include-ignored", includeIgnored, "Include ignored checks in the result output")
	rootCmd.Flags().BoolVar(&allDirs, "force-all-dirs", allDirs, "Don't search for tf files, include everything below provided directory.")
	rootCmd.Flags().BoolVar(&runStatistics, "run-statistics", runStatistics, "View statistics table of current findings.")
	rootCmd.Flags().BoolVar(&ignoreWarnings, "ignore-warnings", ignoreWarnings, "[DEPRECATED] Don't show warnings in the output.")
	rootCmd.Flags().BoolVar(&ignoreInfo, "ignore-info", ignoreWarnings, "[DEPRECATED] Don't show info results in the output.")
	rootCmd.Flags().BoolVarP(&stopOnCheckError, "allow-checks-to-panic", "p", stopOnCheckError, "Allow panics to propagate up from rule checking")
	rootCmd.Flags().StringVarP(&workspace, "workspace", "w", workspace, "Specify a workspace for ignore limits")
	rootCmd.Flags().BoolVar(&passingGif, "gif", passingGif, "Show a celebratory gif in the terminal if no problems are found (default formatter only)")
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
			if version.Version == "" {
				fmt.Println("You are running a locally built version of tfsec.")
			} else {
				fmt.Println(version.Version)
			}
			os.Exit(0)
		}

		if runUpdate {
			if err := updater.Update(); err != nil {
				_ = tml.Printf("Not updating, %s\n", err.Error())
			}
			os.Exit(0)
		}
	},
	RunE: func(cmd *cobra.Command, args []string) error {

		var dir string
		var err error
		var filterResultsList []string
		var outputFile *os.File

		if ignoreWarnings || ignoreInfo {
			fmt.Fprint(os.Stderr, "WARNING: The --ignore-info and --ignore-warnings flags are deprecated and will soon be removed.\n")
		}

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
			tfsecConfig, err = loadConfigFile(configFile)
			if err != nil {
				return err
			}
		} else {
			jsonConfigFile := fmt.Sprintf("%s/%s", tfsecDir, "config.json")
			yamlConfigFile := fmt.Sprintf("%s/%s", tfsecDir, "config.yml")
			if _, err = os.Stat(jsonConfigFile); err == nil {
				tfsecConfig, err = loadConfigFile(jsonConfigFile)
				if err != nil {
					return err
				}
			} else if _, err = os.Stat(yamlConfigFile); err == nil {
				tfsecConfig, err = loadConfigFile(yamlConfigFile)
				if err != nil {
					return err
				}
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
			_, _ = fmt.Fprintf(os.Stderr, "There were errors while processing custom check files. %s", err)
			os.Exit(1)
		}
		debug.Log("Custom checks loaded")

		if len(filterResults) > 0 {
			filterResultsList = strings.Split(filterResults, ",")
		}

		if outputFlag != "" {
			if format == "" {
				format = "text"
			}
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

		if len(tfvarsPaths) == 0 && unusedTfvarsPresent(dir) {
			fmt.Fprintf(os.Stderr, "Warning: A tfvars file was found but not automatically used. Did you mean to specify the --tfvars-file flag?\n")
		}

		debug.Log("Starting parser...")
		modules, err := parser.New(dir, getParserOptions()...).ParseDirectory()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		debug.Log("Starting scanner...")
		results := scanner.New(getScannerOptions()...).Scan(modules)
		results = updateResultSeverity(results)
		results = removeDuplicatesAndUnwanted(results, ignoreWarnings, excludeDownloaded)
		if len(filterResultsList) > 0 {
			var filteredResult []result.Result
			for _, result := range results {
				for _, ruleID := range filterResultsList {
					if result.RuleID == ruleID {
						filteredResult = append(filteredResult, result)
					}
				}
			}
			results = filteredResult
		}

		for _, result := range results {
			metrics.AddResult(result.Severity)
		}

		if runStatistics {
			statistics := scanner.Statistics{}
			for _, result := range results {
				statistics = scanner.AddStatisticsCount(statistics, result)
			}
			statistics.PrintStatisticsTable()
			return nil
		}

		if err := formatter(outputFile, results, dir, getFormatterOptions()...); err != nil {
			return err
		}

		// Soft fail always takes precedence. If set, only execution errors
		// produce a failure exit code (1).
		if softFail {
			return nil
		}

		if detailedExitCode {
			os.Exit(getDetailedExitCode(results))
		}

		// If all failed rules are of LOW severity, then produce a success
		// exit code (0).
		if allInfo(results) {
			return nil
		}

		os.Exit(1)
		return nil
	},
}

func getParserOptions() []parser.Option {
	var opts []parser.Option
	if allDirs {
		opts = append(opts, parser.OptionDoNotSearchTfFiles())
	}
	var validTfVarFiles []string
	if len(tfvarsPaths) > 0 {
		for _, tfvarsPath := range tfvarsPaths {
			tfvp, err := filepath.Abs(tfvarsPath)
			if err != nil {
				fmt.Println(err)
			}
			if _, err := os.Stat(tfvp); err == nil {
				validTfVarFiles = append(validTfVarFiles, tfvp)
			}
		}
		opts = append(opts, parser.OptionWithTFVarsPaths(validTfVarFiles))
	}
	if !ignoreHCLErrors {
		opts = append(opts, parser.OptionStopOnHCLError())
	}

	if workspace != "" {
		opts = append(opts, parser.OptionWithWorkspaceName(workspace))
	}

	return opts
}

func getDetailedExitCode(results []result.Result) int {
	// If there are no failed rules, then produce a success exit code (0).
	if len(results) == 0 || len(results) == countPassedResults(results) {
		return 0
	}

	// If there are some failed rules but they are all of LOW severity, then
	// produce a special failure exit code (2).
	if allInfo(results) {
		return 2
	}

	// If there is any failed check of HIGH or WARNING severity, then
	// produce the regular failure exit code (1).
	return 1
}

func removeDuplicatesAndUnwanted(results []result.Result, ignoreWarnings bool, excludeDownloaded bool) []result.Result {
	reduction := make(map[string]result.Result)

	for _, res := range results {
		reduction[res.HashCode()] = res
	}

	var returnVal []result.Result
	for _, res := range reduction {
		if excludeDownloaded && strings.Contains(res.Range().Filename, fmt.Sprintf("%c.terraform", os.PathSeparator)) {
			continue
		}

		if ignoreWarnings && res.Severity == severity.Medium {
			continue
		}

		if ignoreInfo && res.Severity == severity.Low {
			continue
		}

		returnVal = append(returnVal, res)
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
	if passingGif {
		options = append(options, formatters.PassingGif)
	}
	return options
}

func getScannerOptions() []scanner.Option {
	var options []scanner.Option
	if includePassed {
		options = append(options, scanner.OptionIncludePassed())
	}
	if includeIgnored {
		options = append(options, scanner.OptionIncludeIgnored())
	}
	if workspace != "" {
		options = append(options, scanner.OptionWithWorkspaceName(workspace))
	}

	if stopOnCheckError {
		options = append(options, scanner.OptionStopOnErrors())
	}

	var allExcludedRuleIDs []string
	for _, exclude := range strings.Split(excludedRuleIDs, ",") {
		allExcludedRuleIDs = append(allExcludedRuleIDs, strings.TrimSpace(exclude))
	}
	allExcludedRuleIDs = mergeWithoutDuplicates(allExcludedRuleIDs, tfsecConfig.ExcludedChecks)

        options = append(options, scanner.OptionExcludeRules(allExcludedRuleIDs))

	var allIncludedRuleIDs []string
	if len(includedRuleIDs) > 0 {
		for _, include := range strings.Split(includedRuleIDs, ",") {
			allIncludedRuleIDs = append(allIncludedRuleIDs, strings.TrimSpace(include))
		}
	}
	allIncludedRuleIDs = mergeWithoutDuplicates(allIncludedRuleIDs, tfsecConfig.IncludedChecks)

	options = append(options, scanner.OptionIncludeRules(allIncludedRuleIDs))
	return options
}

func mergeWithoutDuplicates(left, right []string) []string {
	all := append(left, right...)
	var set = map[string]bool{}
	for _, x := range all {
		set[x] = true
	}
	var results []string
	for x := range set {
		results = append(results, x)
	}

	return results
}

func allInfo(results []result.Result) bool {
	for _, res := range results {
		if res.Severity != severity.Low && res.Status != result.Passed && res.Status != result.Ignored {
			return false
		}
	}
	return true
}

func updateResultSeverity(results []result.Result) []result.Result {
	overrides := tfsecConfig.SeverityOverrides

	if len(overrides) == 0 {
		return results
	}

	var overriddenResults []result.Result
	for _, res := range results {
		for code, sev := range overrides {
			if res.RuleID == code || res.LegacyRuleID == code {
				res.WithSeverity(severity.Severity(sev))
			}
		}
		overriddenResults = append(overriddenResults, res)
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

func loadConfigFile(configFilePath string) (*config.Config, error) {
	debug.Log("loading config file %s", configFilePath)
	return config.LoadConfig(configFilePath)
}

func countPassedResults(results []result.Result) int {
	passed := 0

	for _, res := range results {
		if res.Status == result.Passed {
			passed++
		}
	}

	return passed
}

func unusedTfvarsPresent(checkDir string) bool {
	glob := fmt.Sprintf("%s/*.tfvars", checkDir)
	debug.Log("checking for tfvars files using glob: %s", glob)
	if matches, err := filepath.Glob(glob); err == nil && len(matches) > 0 {
		return true
	}
	return false
}
