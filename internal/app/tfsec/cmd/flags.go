package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/spf13/cobra"

	scanner "github.com/aquasecurity/defsec/pkg/scanners/terraform"
	"github.com/aquasecurity/defsec/pkg/severity"

	"github.com/aquasecurity/defsec/pkg/state"
	"github.com/aquasecurity/tfsec/internal/pkg/legacy"
)

var showVersion bool
var runUpdate bool
var disableColours bool
var format string
var softFail bool
var filterResults string
var excludedRuleIDs string
var tfvarsPaths []string
var excludePaths []string
var outputFlag string
var customCheckDir string
var configFile string
var conciseOutput bool
var excludeDownloaded bool
var includePassed bool
var includeIgnored bool
var allDirs bool
var migrateIgnores bool
var runStatistics bool
var ignoreHCLErrors bool
var stopOnCheckError bool
var workspace string
var singleThreadedMode bool
var disableGrouping bool
var debug bool
var minimumSeverity string
var disableIgnores bool
var regoPolicyDir string
var printRegoInput bool
var noModuleDownloads bool

func resetFlagsToDefaults() {
	showVersion = false
	runUpdate = false
	disableColours = false
	format = "lovely"
	softFail = false
	filterResults = ""
	excludedRuleIDs = ""
	tfvarsPaths = nil
	excludePaths = nil
	outputFlag = ""
	customCheckDir = ""
	configFile = ""
	conciseOutput = false
	excludeDownloaded = false
	includePassed = false
	includeIgnored = false
	allDirs = false
	migrateIgnores = false
	runStatistics = false
	ignoreHCLErrors = false
	stopOnCheckError = false
	workspace = "default"
	singleThreadedMode = false
	disableGrouping = false
	debug = false
	minimumSeverity = ""
	disableIgnores = false
	regoPolicyDir = ""
	printRegoInput = false
	noModuleDownloads = false
}

func configureFlags(cmd *cobra.Command) {

	resetFlagsToDefaults()

	cmd.Flags().BoolVar(&singleThreadedMode, "single-thread", singleThreadedMode, "Run checks using a single thread")
	cmd.Flags().BoolVarP(&disableGrouping, "disable-grouping", "G", disableGrouping, "Disable grouping of similar results")
	cmd.Flags().BoolVar(&ignoreHCLErrors, "ignore-hcl-errors", ignoreHCLErrors, "Stop and report an error if an HCL parse error is encountered")
	cmd.Flags().BoolVar(&disableColours, "no-colour", disableColours, "Disable coloured output")
	cmd.Flags().BoolVar(&disableColours, "no-color", disableColours, "Disable colored output (American style!)")
	cmd.Flags().BoolVarP(&showVersion, "version", "v", showVersion, "Show version information and exit")
	cmd.Flags().BoolVar(&runUpdate, "update", runUpdate, "Update to latest version")
	cmd.Flags().BoolVar(&migrateIgnores, "migrate-ignores", migrateIgnores, "Migrate ignore codes to the new ID structure")
	cmd.Flags().StringVarP(&format, "format", "f", format, "Select output format: lovely, json, csv, checkstyle, junit, sarif. To use multiple formats, separate with a comma and specify a base output filename with --out. A file will be written for each type. The first format will additionally be written stdout.")
	cmd.Flags().StringVarP(&excludedRuleIDs, "exclude", "e", excludedRuleIDs, "Provide comma-separated list of rule IDs to exclude from run.")
	cmd.Flags().StringVar(&filterResults, "filter-results", filterResults, "Filter results to return specific checks only (supports comma-delimited input).")
	cmd.Flags().BoolVarP(&softFail, "soft-fail", "s", softFail, "Runs checks but suppresses error code")
	cmd.Flags().StringSliceVar(&tfvarsPaths, "tfvars-file", tfvarsPaths, "Path to .tfvars file, can be used multiple times and evaluated in order of specification")
	cmd.Flags().StringSliceVar(&excludePaths, "exclude-path", excludePaths, "Folder path to exclude, can be used multiple times and evaluated in order of specification")
	cmd.Flags().StringVarP(&outputFlag, "out", "O", outputFlag, "Set output file. This filename will have a format descriptor appended if multiple formats are specified with --format")
	cmd.Flags().StringVar(&customCheckDir, "custom-check-dir", customCheckDir, "Explicitly the custom checks dir location")
	cmd.Flags().StringVar(&configFile, "config-file", configFile, "Config file to use during run")
	cmd.Flags().BoolVar(&debug, "debug", debug, "Enable debug logging (same as verbose)")
	cmd.Flags().BoolVar(&debug, "verbose", debug, "Enable verbose logging (same as debug)")
	cmd.Flags().BoolVar(&conciseOutput, "concise-output", conciseOutput, "Reduce the amount of output and no statistics")
	cmd.Flags().BoolVar(&excludeDownloaded, "exclude-downloaded-modules", excludeDownloaded, "Remove results for downloaded modules in .terraform folder")
	cmd.Flags().BoolVar(&includePassed, "include-passed", includePassed, "Include passed checks in the result output")
	cmd.Flags().BoolVar(&includeIgnored, "include-ignored", includeIgnored, "Include ignored checks in the result output")
	cmd.Flags().BoolVar(&disableIgnores, "no-ignores", disableIgnores, "Do not apply any ignore rules - normally ignored checks will fail")
	cmd.Flags().BoolVar(&allDirs, "force-all-dirs", allDirs, "Don't search for tf files, include everything below provided directory.")
	cmd.Flags().BoolVar(&runStatistics, "run-statistics", runStatistics, "View statistics table of current findings.")
	cmd.Flags().BoolVarP(&stopOnCheckError, "allow-checks-to-panic", "p", stopOnCheckError, "Allow panics to propagate up from rule checking")
	cmd.Flags().StringVarP(&workspace, "workspace", "w", workspace, "Specify a workspace for ignore limits")
	cmd.Flags().StringVarP(&minimumSeverity, "minimum-severity", "m", minimumSeverity, "The minimum severity to report. One of CRITICAL, HIGH, MEDIUM, LOW.")
	cmd.Flags().StringVar(&regoPolicyDir, "rego-policy-dir", regoPolicyDir, "Directory to load rego policies from (recursively).")
	cmd.Flags().BoolVar(&printRegoInput, "print-rego-input", printRegoInput, "Print a JSON representation of the input supplied to rego policies.")
	cmd.Flags().BoolVar(&noModuleDownloads, "no-module-downloads", noModuleDownloads, "Do not download remote modules.")

	_ = cmd.Flags().MarkHidden("allow-checks-to-panic")
}

func makePathsRelativeToFSRoot(fsRoot string, paths []string) ([]string, error) {
	var output []string
	for _, path := range paths {
		rel, err := makePathRelativeToFSRoot(fsRoot, path)
		if err != nil {
			return nil, err
		}
		output = append(output, rel)
	}
	return output, nil
}

func makePathRelativeToFSRoot(fsRoot, path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	root, dir, err := splitRoot(abs)
	if err != nil {
		return "", err
	}
	if root != fsRoot {
		return "", fmt.Errorf("cannot use a different volume to the one being scanned")
	}
	return dir, nil
}

func configureOptions(cmd *cobra.Command, fsRoot string) ([]scanner.Option, error) {

	var options []scanner.Option
	options = append(
		options,
		scanner.OptionWithSingleThread(singleThreadedMode),
		scanner.OptionStopOnHCLError(!ignoreHCLErrors),
		scanner.OptionStopOnRuleErrors(stopOnCheckError),
		scanner.OptionSkipDownloaded(excludeDownloaded),
		scanner.OptionScanAllDirectories(allDirs),
		scanner.OptionWithWorkspaceName(workspace),
		scanner.OptionWithAlternativeIDProvider(legacy.FindIDs),
		scanner.OptionWithPolicyNamespaces("custom"),
		scanner.OptionWithDownloads(!noModuleDownloads),
	)

	if len(excludePaths) > 0 {
		options = append(options, scanner.OptionWithResultsFilter(func(results scan.Results) scan.Results {
			for i, result := range results {
				rng := result.Range()
				if rng == nil {
					continue
				}
				for _, exclude := range excludePaths {
					exclude = fmt.Sprintf("%c%s%[1]c", filepath.Separator, filepath.Clean(exclude))
					if strings.Contains(
						fmt.Sprintf("%c%s%[1]c", filepath.Separator, rng.GetFilename()),
						exclude,
					) {
						results[i].OverrideStatus(scan.StatusIgnored)
						break
					}
				}
			}
			return results
		}))
	}

	if len(tfvarsPaths) > 0 {
		fixedPaths, err := makePathsRelativeToFSRoot(fsRoot, tfvarsPaths)
		if err != nil {
			return nil, fmt.Errorf("tfvars problem: %w", err)
		}
		options = append(options, scanner.OptionWithTFVarsPaths(fixedPaths))
	}

	if regoPolicyDir != "" {
		fixedPath, err := makePathRelativeToFSRoot(fsRoot, regoPolicyDir)
		if err != nil {
			return nil, fmt.Errorf("rego policy dir problem: %w", err)
		}
		options = append(options, scanner.OptionWithPolicyDirs(fixedPath))
	}

	if disableIgnores {
		options = append(options, scanner.OptionNoIgnores())
	}

	if minimumSeverity != "" {
		sev := severity.StringToSeverity(minimumSeverity)
		if sev == severity.None {
			return nil, fmt.Errorf("'%s' is not a valid severity - should be one of CRITICAL, HIGH, MEDIUM, LOW", minimumSeverity)
		}
		options = append(options, scanner.OptionWithMinimumSeverity(sev))
	}

	if filterResults != "" {
		longIDs := strings.Split(filterResults, ",")
		options = append(options, scanner.OptionIncludeRules(longIDs))
	}

	if excludedRuleIDs != "" {
		options = append(options, scanner.OptionExcludeRules(strings.Split(excludedRuleIDs, ",")))
	}

	if debug {
		options = append(options, scanner.OptionWithDebug(os.Stderr))
	}

	if printRegoInput {
		options = append(options, scanner.OptionWithStateFunc(func(s *state.State) {
			data, _ := json.Marshal(s.ToRego())
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "\n%s\n\n", string(data))
		}))
	}

	return options, nil
}
