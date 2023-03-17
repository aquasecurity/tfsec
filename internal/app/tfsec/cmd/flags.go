package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/aquasecurity/defsec/pkg/scanners/options"
	"github.com/aquasecurity/tfsec/internal/pkg/custom"
	"github.com/google/uuid"

	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"

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
var excludeIgnoresIDs string
var tfvarsPaths []string
var excludePaths []string
var outputFlag string
var customCheckDir string
var customCheckUrl string
var configFile string
var configFileUrl string
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
var codeTheme string
var noCode bool

func configureFlags(cmd *cobra.Command) {
	v := viper.New()
	v.SetEnvPrefix("TFSEC")
	v.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	v.AutomaticEnv()
	v.SetTypeByDefaultValue(true)

	cmd.Flags().BoolVar(&singleThreadedMode, "single-thread", false, "Run checks using a single thread")
	cmd.Flags().BoolVarP(&disableGrouping, "disable-grouping", "G", false, "Disable grouping of similar results")
	cmd.Flags().BoolVar(&ignoreHCLErrors, "ignore-hcl-errors", false, "Do not report an error if an HCL parse error is encountered")
	cmd.Flags().BoolVar(&disableColours, "no-colour", false, "Disable coloured output")
	cmd.Flags().BoolVar(&disableColours, "no-color", false, "Disable colored output (American style!)")
	cmd.Flags().BoolVarP(&showVersion, "version", "v", false, "Show version information and exit")
	cmd.Flags().BoolVar(&runUpdate, "update", false, "Update to latest version")
	cmd.Flags().BoolVar(&migrateIgnores, "migrate-ignores", false, "Migrate ignore codes to the new ID structure")
	cmd.Flags().StringVarP(&format, "format", "f", "lovely", "Select output format: lovely, json, csv, checkstyle, junit, sarif, text, markdown, html, gif. To use multiple formats, separate with a comma and specify a base output filename with --out. A file will be written for each type. The first format will additionally be written stdout.")
	cmd.Flags().StringVarP(&excludedRuleIDs, "exclude", "e", "", "Provide comma-separated list of rule IDs to exclude from run.")
	cmd.Flags().StringVarP(&excludeIgnoresIDs, "exclude-ignores", "E", "", "Provide comma-separated list of ignored rule to exclude from run.")
	cmd.Flags().StringVar(&filterResults, "filter-results", "", "Filter results to return specific checks only (supports comma-delimited input).")
	cmd.Flags().BoolVarP(&softFail, "soft-fail", "s", false, "Runs checks but suppresses error code")
	cmd.Flags().StringSliceVar(&tfvarsPaths, "tfvars-file", nil, "Path to .tfvars file, can be used multiple times and evaluated in order of specification")
	cmd.Flags().StringSliceVar(&tfvarsPaths, "var-file", nil, "Path to .tfvars file, can be used multiple times and evaluated in order of specification (same functionality as --tfvars-file but consistent with Terraform)")
	cmd.Flags().StringSliceVar(&excludePaths, "exclude-path", nil, "Folder path to exclude, can be used multiple times and evaluated in order of specification")
	cmd.Flags().StringVarP(&outputFlag, "out", "O", "", "Set output file. This filename will have a format descriptor appended if multiple formats are specified with --format")
	cmd.Flags().StringVar(&customCheckDir, "custom-check-dir", "", "Explicitly set the custom checks dir location")
	cmd.Flags().StringVar(&customCheckUrl, "custom-check-url", "",
		"Download a custom check file from a remote location. Must be json or yaml")
	cmd.Flags().StringVar(&configFile, "config-file", "", "Config file to use during run")
	cmd.Flags().StringVar(&configFileUrl, "config-file-url", "", "Config file to download from a remote location. Must be json or yaml")
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
	cmd.Flags().StringVar(&codeTheme, "code-theme", "dark", "Theme for annotated code. Either 'light' or 'dark'.")
	cmd.Flags().BoolVar(&noCode, "no-code", false, "Don't include the code snippets in the output.")

	_ = cmd.Flags().MarkHidden("allow-checks-to-panic")

	bindFlags(cmd, v)
}

// Bind each cobra flag to its associated viper configuration (config file and environment variable)
func bindFlags(cmd *cobra.Command, v *viper.Viper) {
	cmd.Flags().VisitAll(func(f *pflag.Flag) {
		// Determine the naming convention of the flags when represented in the config file
		configName := f.Name

		// Apply the viper config value to the flag when the flag is not set and viper has a value
		if !f.Changed && v.IsSet(configName) {
			val := v.Get(configName)
			err := cmd.Flags().Set(f.Name, fmt.Sprintf("%v", val))
			if err != nil {
				logger.Log("failed to set %v with %v", f.Name, val)
			}
		}
	})
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
		options.ScannerWithRegoOnly(regoOnly),
		options.ScannerWithEmbeddedPolicies(true),
	)

	if len(excludePaths) > 0 {
		excludePaths = explodeGlob(excludePaths, fsRoot, dir)
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

	if excludeIgnoresIDs != "" {
		scannerOptions = append(scannerOptions, scanner.ScannerWithExcludeIgnores(strings.Split(excludeIgnoresIDs, ",")))
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

func explodeGlob(paths []string, root string, dir string) []string {
	var exploded []string

	for _, path := range paths {
		if !strings.Contains(path, "*") {
			exploded = append(exploded, path)
			continue
		}
		if globPaths, err := filepath.Glob(filepath.Join(dir, path)); err == nil {
			for _, globPath := range globPaths {
				exploded = append(exploded, strings.TrimPrefix(globPath, root))
			}
		}
	}

	return exploded
}

func applyConfigFiles(options []options.ScannerOption, dir string) ([]options.ScannerOption, error) {
	if configFileUrl != "" {
		if remoteConfigDownloaded() {
			defer func() { _ = os.Remove(configFile) }()
		}
	}

	if configFile == "" {
		configDir := filepath.Join(dir, ".tfsec")
		for _, filename := range []string{"config.json", "config.yml", "config.yaml"} {
			path := filepath.Join(configDir, filename)
			if _, err := os.Stat(path); err == nil {
				configFile = path
				logger.Log("Found default config file at %s", configFile)
				break
			}
		}
	}

	if configFile != "" {
		if conf, err := config.LoadConfig(configFile); err == nil {
			logger.Log("Loaded config file at %s", configFile)
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
			if len(conf.GetValidExcludedChecks()) > 0 {
				options = append(options, scanner.ScannerWithExcludedRules(append(conf.GetValidExcludedChecks(), excludedRuleIDs)))
			}
			if len(conf.ExcludeIgnores) > 0 {
				options = append(options, scanner.ScannerWithExcludeIgnores(append(conf.ExcludeIgnores, excludeIgnoresIDs)))
			}
		} else {
			logger.Log("Failed to load config file: %s", err)
		}
	}

	return configureCustomChecks(options, dir)
}

func configureCustomChecks(options []options.ScannerOption, dir string) ([]options.ScannerOption, error) {
	if customCheckUrl != "" {
		if remoteCustomCheckDownloaded() {
			defer func() { _ = os.RemoveAll(customCheckDir) }()
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

func remoteConfigDownloaded() bool {
	tempFile := filepath.Join(os.TempDir(), filepath.Base(configFileUrl))

	/* #nosec */
	resp, err := http.Get(configFileUrl)
	if err != nil || resp.StatusCode != http.StatusOK {
		return false
	}
	defer func() { _ = resp.Body.Close() }()

	configContent, err := io.ReadAll(resp.Body)
	if err != nil {
		return false
	}

	if err := os.WriteFile(tempFile, configContent, os.ModePerm); err != nil {
		return false
	}
	configFile = tempFile
	return true
}

func remoteCustomCheckDownloaded() bool {
	customTempDir, err := os.MkdirTemp(os.TempDir(), fmt.Sprintf("tfsec_custom_check_%s", uuid.NewString()))
	if err != nil {
		return false
	}
	tempFile := filepath.Join(customTempDir, filepath.Base(customCheckUrl))

	/* #nosec */
	resp, err := http.Get(customCheckUrl)
	if err != nil || resp.StatusCode != http.StatusOK {
		return false
	}
	defer func() { _ = resp.Body.Close() }()

	customCheckContent, err := io.ReadAll(resp.Body)
	if err != nil {
		return false
	}

	if err := os.WriteFile(tempFile, customCheckContent, os.ModePerm); err != nil {
		return false
	}
	customCheckDir = customTempDir
	return true
}
