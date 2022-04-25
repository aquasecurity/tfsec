package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/aquasecurity/defsec/pkg/scanners/options"

	"github.com/aquasecurity/tfsec/internal/pkg/custom"

	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/spf13/cobra"

	scanner "github.com/aquasecurity/defsec/pkg/scanners/terraform"
	"github.com/aquasecurity/defsec/pkg/severity"

	"github.com/aquasecurity/defsec/pkg/state"
	"github.com/aquasecurity/tfsec/internal/pkg/config"
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
var regoOnly bool

func configureFlags(cmd *cobra.Command) {

	cmd.Flags().BoolVar(&singleThreadedMode, "single-thread", false, "Run checks using a single thread")
	cmd.Flags().BoolVarP(&disableGrouping, "disable-grouping", "G", false, "Disable grouping of similar results")
	cmd.Flags().BoolVar(&ignoreHCLErrors, "ignore-hcl-errors", false, "Do not report an error if an HCL parse error is encountered")
	cmd.Flags().BoolVar(&disableColours, "no-colour", false, "Disable coloured output")
	cmd.Flags().BoolVar(&disableColours, "no-color", false, "Disable colored output (American style!)")
	cmd.Flags().BoolVarP(&showVersion, "version", "v", false, "Show version information and exit")
	cmd.Flags().BoolVar(&runUpdate, "update", false, "Update to latest version")
	cmd.Flags().BoolVar(&migrateIgnores, "migrate-ignores", false, "Migrate ignore codes to the new ID structure")
	cmd.Flags().StringVarP(&format, "format", "f", "lovely", "Select output format: lovely, json, csv, checkstyle, junit, sarif. To use multiple formats, separate with a comma and specify a base output filename with --out. A file will be written for each type. The first format will additionally be written stdout.")
	cmd.Flags().StringVarP(&excludedRuleIDs, "exclude", "e", "", "Provide comma-separated list of rule IDs to exclude from run.")
	cmd.Flags().StringVar(&filterResults, "filter-results", "", "Filter results to return specific checks only (supports comma-delimited input).")
	cmd.Flags().BoolVarP(&softFail, "soft-fail", "s", false, "Runs checks but suppresses error code")
	cmd.Flags().StringSliceVar(&tfvarsPaths, "tfvars-file", nil, "Path to .tfvars file, can be used multiple times and evaluated in order of specification")
	cmd.Flags().StringSliceVar(&tfvarsPaths, "var-file", nil, "Path to .tfvars file, can be used multiple times and evaluated in order of specification (same functionaility as --tfvars-file but consistent with Terraform)")
	cmd.Flags().StringSliceVar(&excludePaths, "exclude-path", nil, "Folder path to exclude, can be used multiple times and evaluated in order of specification")
	cmd.Flags().StringVarP(&outputFlag, "out", "O", "", "Set output file. This filename will have a format descriptor appended if multiple formats are specified with --format")
	cmd.Flags().StringVar(&customCheckDir, "custom-check-dir", "", "Explicitly the custom checks dir location")
	cmd.Flags().StringVar(&configFile, "config-file", "", "Config file to use during run")
	cmd.Flags().BoolVar(&debug, "debug", false, "Enable debug logging (same as verbose)")
	cmd.Flags().BoolVar(&debug, "verbose", false, "Enable verbose logging (same as debug)")
	cmd.Flags().BoolVar(&conciseOutput, "concise-output", false, "Reduce the amount of output and no statistics")
	cmd.Flags().BoolVar(&excludeDownloaded, "exclude-downloaded-modules", false, "Remove results for downloaded modules in .terraform folder")
	cmd.Flags().BoolVar(&includePassed, "include-passed", false, "Include passed checks in the result output")
	cmd.Flags().BoolVar(&includeIgnored, "include-ignored", false, "Include ignored checks in the result output")
	cmd.Flags().BoolVar(&disableIgnores, "no-ignores", false, "Do not apply any ignore rules - normally ignored checks will fail")
	cmd.Flags().BoolVar(&allDirs, "force-all-dirs", false, "Don't search for tf files, include everything below provided directory.")
	cmd.Flags().BoolVar(&runStatistics, "run-statistics", false, "View statistics table of current findings.")
	cmd.Flags().BoolVarP(&stopOnCheckError, "allow-checks-to-panic", "p", false, "Allow panics to propagate up from rule checking")
	cmd.Flags().StringVarP(&workspace, "workspace", "w", "default", "Specify a workspace for ignore limits")
	cmd.Flags().StringVarP(&minimumSeverity, "minimum-severity", "m", "", "The minimum severity to report. One of CRITICAL, HIGH, MEDIUM, LOW.")
	cmd.Flags().StringVar(&regoPolicyDir, "rego-policy-dir", "", "Directory to load rego policies from (recursively).")
	cmd.Flags().BoolVar(&printRegoInput, "print-rego-input", false, "Print a JSON representation of the input supplied to rego policies.")
	cmd.Flags().BoolVar(&noModuleDownloads, "no-module-downloads", false, "Do not download remote modules.")
	cmd.Flags().BoolVar(&regoOnly, "rego-only", false, "Run rego policies exclusively.")

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

func excludeFunc(excludePaths []string) func(results scan.Results) scan.Results {
	return func(results scan.Results) scan.Results {
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
	}
}

func configureOptions(cmd *cobra.Command, fsRoot, dir string) ([]options.ScannerOption, error) {

	var scannerOptions []options.ScannerOption
	scannerOptions = append(
		scannerOptions,
		scanner.ScannerWithSingleThread(singleThreadedMode),
		scanner.ScannerWithStopOnHCLError(!ignoreHCLErrors),
		scanner.ScannerWithStopOnRuleErrors(stopOnCheckError),
		scanner.ScannerWithSkipDownloaded(excludeDownloaded),
		scanner.ScannerWithAllDirectories(allDirs),
		scanner.ScannerWithWorkspaceName(workspace),
		scanner.ScannerWithAlternativeIDProvider(legacy.FindIDs),
		options.ScannerWithPolicyNamespaces("custom"),
		scanner.ScannerWithDownloadsAllowed(!noModuleDownloads),
		scanner.ScannerWithRegoOnly(regoOnly),
	)

	if len(excludePaths) > 0 {
		scannerOptions = append(scannerOptions, scanner.ScannerWithResultsFilter(excludeFunc(excludePaths)))
	}

	if len(tfvarsPaths) > 0 {
		fixedPaths, err := makePathsRelativeToFSRoot(fsRoot, tfvarsPaths)
		if err != nil {
			return nil, fmt.Errorf("tfvars problem: %w", err)
		}
		scannerOptions = append(scannerOptions, scanner.ScannerWithTFVarsPaths(fixedPaths...))
	}

	if regoPolicyDir != "" {
		fixedPath, err := makePathRelativeToFSRoot(fsRoot, regoPolicyDir)
		if err != nil {
			return nil, fmt.Errorf("rego policy dir problem: %w", err)
		}
		scannerOptions = append(scannerOptions, options.ScannerWithPolicyDirs(fixedPath))
	}

	if disableIgnores {
		scannerOptions = append(scannerOptions, scanner.ScannerWithNoIgnores())
	}

	if minimumSeverity != "" {
		sev := severity.StringToSeverity(minimumSeverity)
		if sev == severity.None {
			return nil, fmt.Errorf("'%s' is not a valid severity - should be one of CRITICAL, HIGH, MEDIUM, LOW", minimumSeverity)
		}
		scannerOptions = append(scannerOptions, scanner.ScannerWithMinimumSeverity(sev))
	}

	if filterResults != "" {
		longIDs := strings.Split(filterResults, ",")
		scannerOptions = append(scannerOptions, scanner.ScannerWithIncludedRules(longIDs))
	}

	if excludedRuleIDs != "" {
		scannerOptions = append(scannerOptions, scanner.ScannerWithExcludedRules(strings.Split(excludedRuleIDs, ",")))
	}

	if debug {
		scannerOptions = append(scannerOptions, options.ScannerWithDebug(cmd.ErrOrStderr()))
	}

	if printRegoInput {
		scannerOptions = append(scannerOptions, scanner.ScannerWithStateFunc(func(s *state.State) {
			data, _ := json.Marshal(s.ToRego())
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "\n%s\n\n", string(data))
		}))
	}

	return applyConfigFiles(scannerOptions, dir)
}

func applyConfigFiles(options []options.ScannerOption, dir string) ([]options.ScannerOption, error) {
	if configFile == "" {
		configDir := filepath.Join(dir, ".tfsec")
		for _, filename := range []string{"config.json", "config.yml", "config.yaml"} {
			path := filepath.Join(configDir, filename)
			if _, err := os.Stat(path); err == nil {
				configFile = path
				break
			}
		}
	}
	if configFile != "" {
		if conf, err := config.LoadConfig(configFile); err == nil {
			if !minVersionSatisfied(conf) {
				return nil, fmt.Errorf("minimum tfsec version requirement not satisfied")
			}
			if conf.MinimumSeverity != "" {
				options = append(options, scanner.ScannerWithMinimumSeverity(severity.StringToSeverity(conf.MinimumSeverity)))
			}
			if len(conf.SeverityOverrides) > 0 {
				options = append(options, scanner.ScannerWithSeverityOverrides(conf.SeverityOverrides))
			}
			if len(conf.IncludedChecks) > 0 {
				options = append(options, scanner.ScannerWithIncludedRules(conf.IncludedChecks))
			}
			if len(conf.ExcludedChecks) > 0 {
				options = append(options, scanner.ScannerWithExcludedRules(append(conf.ExcludedChecks, excludedRuleIDs)))
			}
		}
	}
	if customCheckDir == "" {
		customCheckDir = filepath.Join(dir, ".tfsec")
	}
	if err := custom.Load(customCheckDir); err != nil {
		return nil, fmt.Errorf("failed to load custom checks from %s: %w", customCheckDir, err)
	}
	return options, nil
}
