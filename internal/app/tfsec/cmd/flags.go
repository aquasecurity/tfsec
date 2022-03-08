package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/tfsec/pkg/scanner"
)

var showVersion = false
var runUpdate = false
var disableColours = false
var format string
var softFail = false
var filterResults string
var excludedRuleIDs string
var tfvarsPaths []string
var excludePaths []string
var outputFlag string
var customCheckDir string
var configFile string
var conciseOutput = false
var excludeDownloaded = false
var includePassed = false
var includeIgnored = false
var allDirs = false
var migrateIgnores = false
var runStatistics bool
var ignoreHCLErrors bool
var stopOnCheckError bool
var workspace = "default"
var singleThreadedMode bool
var disableGrouping bool
var debug bool
var minimumSeverity string

func init() {
	rootCmd.Flags().BoolVar(&singleThreadedMode, "single-thread", singleThreadedMode, "Run checks using a single thread")
	rootCmd.Flags().BoolVarP(&disableGrouping, "disable-grouping", "G", disableGrouping, "Disable grouping of similar results")
	rootCmd.Flags().BoolVar(&ignoreHCLErrors, "ignore-hcl-errors", ignoreHCLErrors, "Stop and report an error if an HCL parse error is encountered")
	rootCmd.Flags().BoolVar(&disableColours, "no-colour", disableColours, "Disable coloured output")
	rootCmd.Flags().BoolVar(&disableColours, "no-color", disableColours, "Disable colored output (American style!)")
	rootCmd.Flags().BoolVarP(&showVersion, "version", "v", showVersion, "Show version information and exit")
	rootCmd.Flags().BoolVar(&runUpdate, "update", runUpdate, "Update to latest version")
	rootCmd.Flags().BoolVar(&migrateIgnores, "migrate-ignores", migrateIgnores, "Migrate ignore codes to the new ID structure")
	rootCmd.Flags().StringVarP(&format, "format", "f", format, "Select output format: default, json, csv, checkstyle, junit, sarif. To use multiple formats, separate with a comma and specify a base output filename with --out. A file will be written for each type. The first format will additionally be written stdout.")
	rootCmd.Flags().StringVarP(&excludedRuleIDs, "exclude", "e", excludedRuleIDs, "Provide comma-separated list of rule IDs to exclude from run.")
	rootCmd.Flags().StringVar(&filterResults, "filter-results", filterResults, "Filter results to return specific checks only (supports comma-delimited input).")
	rootCmd.Flags().BoolVarP(&softFail, "soft-fail", "s", softFail, "Runs checks but suppresses error code")
	rootCmd.Flags().StringSliceVar(&tfvarsPaths, "tfvars-file", tfvarsPaths, "Path to .tfvars file, can be used multiple times and evaluated in order of specification")
	rootCmd.Flags().StringSliceVar(&excludePaths, "exclude-path", excludePaths, "Folder path to exclude, can be used multiple times and evaluated in order of specification")
	rootCmd.Flags().StringVarP(&outputFlag, "out", "O", outputFlag, "Set output file. This filename will have a format descriptor appended if multiple formats are specified with --format")
	rootCmd.Flags().StringVar(&customCheckDir, "custom-check-dir", customCheckDir, "Explicitly the custom checks dir location")
	rootCmd.Flags().StringVar(&configFile, "config-file", configFile, "Config file to use during run")
	rootCmd.Flags().BoolVar(&debug, "debug", debug, "Enable debug logging (same as verbose)")
	rootCmd.Flags().BoolVar(&debug, "verbose", debug, "Enable verbose logging (same as debug)")
	rootCmd.Flags().BoolVar(&conciseOutput, "concise-output", conciseOutput, "Reduce the amount of output and no statistics")
	rootCmd.Flags().BoolVar(&excludeDownloaded, "exclude-downloaded-modules", excludeDownloaded, "Remove results for downloaded modules in .terraform folder")
	rootCmd.Flags().BoolVar(&includePassed, "include-passed", includePassed, "Include passed checks in the result output")
	rootCmd.Flags().BoolVar(&includeIgnored, "include-ignored", includeIgnored, "Include ignored checks in the result output")
	rootCmd.Flags().BoolVar(&allDirs, "force-all-dirs", allDirs, "Don't search for tf files, include everything below provided directory.")
	rootCmd.Flags().BoolVar(&runStatistics, "run-statistics", runStatistics, "View statistics table of current findings.")
	rootCmd.Flags().BoolVarP(&stopOnCheckError, "allow-checks-to-panic", "p", stopOnCheckError, "Allow panics to propagate up from rule checking")
	rootCmd.Flags().StringVarP(&workspace, "workspace", "w", workspace, "Specify a workspace for ignore limits")
	rootCmd.Flags().StringVarP(&minimumSeverity, "minimum-severity", "m", minimumSeverity, "The minimum severity to report. One of CRITICAL, HIGH, MEDIUM, LOW.")
	_ = rootCmd.Flags().MarkHidden("allow-checks-to-panic")
}

func configureOptions(dir string) ([]scanner.Option, error) {
	var options []scanner.Option
	options = append(options, scanner.OptionWithSingleThread(singleThreadedMode))
	options = append(options, scanner.OptionStopOnHCLError(!ignoreHCLErrors))
	options = append(options, scanner.OptionStopOnRuleErrors(stopOnCheckError))
	options = append(options, scanner.OptionWithTFVarsPaths(tfvarsPaths))
	options = append(options, scanner.OptionWithExcludePaths(excludePaths))
	options = append(options, scanner.OptionSkipDownloaded(excludeDownloaded))
	options = append(options, scanner.OptionIncludePassed(includePassed))
	options = append(options, scanner.OptionIncludeIgnored(includeIgnored))
	options = append(options, scanner.OptionScanAllDirectories(allDirs))
	options = append(options, scanner.OptionWithWorkspaceName(workspace))

	if minimumSeverity != "" {
		sev := severity.StringToSeverity(minimumSeverity)
		if sev == severity.None {
			return nil, fmt.Errorf("'%s' is not a valid severity - should be one of CRITICAL, HIGH, MEDIUM, LOW", minimumSeverity)
		}
		options = append(options, scanner.OptionWithMinimumSeverity(sev))
	}

	if filterResults != "" {
		longIDs := strings.Split(filterResults, ",")
		options = append(options, scanner.OptionWithIncludeOnlyResults(longIDs))
	}

	if excludedRuleIDs != "" {
		options = append(options, scanner.OptionExcludeRules(strings.Split(excludedRuleIDs, ",")))
	}

	if configFile != "" {
		options = append(options, scanner.OptionWithConfigFile(configFile))
	} else {
		configDir := filepath.Join(dir, ".tfsec")
		for _, filename := range []string{"config.json", "config.yml", "config.yaml"} {
			path := filepath.Join(configDir, filename)
			if _, err := os.Stat(path); err == nil {
				options = append(options, scanner.OptionWithConfigFile(path))
				break
			}
		}
	}
	if customCheckDir != "" {
		options = append(options, scanner.OptionWithCustomCheckDir(customCheckDir))
	} else {
		customDir := filepath.Join(dir, ".tfsec")
		options = append(options, scanner.OptionWithCustomCheckDir(customDir))
	}
	if debug {
		options = append(options, scanner.OptionWithDebugWriter(os.Stderr))
	}
	return options, nil
}
