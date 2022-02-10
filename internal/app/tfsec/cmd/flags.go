package cmd

import (
    "github.com/aquasecurity/tfsec/internal/pkg/config"
    "github.com/aquasecurity/tfsec/internal/pkg/debug"
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
var tfsecConfig = &config.Config{}
var conciseOutput = false
var excludeDownloaded = false
var includePassed = false
var includeIgnored = false
var allDirs = false
var migrateIgnores = false
var runStatistics bool
var ignoreHCLErrors bool
var stopOnCheckError bool
var workspace string
var singleThreadedMode bool
var disableGrouping bool

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
    rootCmd.Flags().BoolVar(&debug.Enabled, "debug", debug.Enabled, "Enable debug logging (same as verbose)")
    rootCmd.Flags().BoolVar(&debug.Enabled, "verbose", debug.Enabled, "Enable verbose logging (same as debug)")
    rootCmd.Flags().BoolVar(&conciseOutput, "concise-output", conciseOutput, "Reduce the amount of output and no statistics")
    rootCmd.Flags().BoolVar(&excludeDownloaded, "exclude-downloaded-modules", excludeDownloaded, "Remove results for downloaded modules in .terraform folder")
    rootCmd.Flags().BoolVar(&includePassed, "include-passed", includePassed, "Include passed checks in the result output")
    rootCmd.Flags().BoolVar(&includeIgnored, "include-ignored", includeIgnored, "Include ignored checks in the result output")
    rootCmd.Flags().BoolVar(&allDirs, "force-all-dirs", allDirs, "Don't search for tf files, include everything below provided directory.")
    rootCmd.Flags().BoolVar(&runStatistics, "run-statistics", runStatistics, "View statistics table of current findings.")
    rootCmd.Flags().BoolVarP(&stopOnCheckError, "allow-checks-to-panic", "p", stopOnCheckError, "Allow panics to propagate up from rule checking")
    rootCmd.Flags().StringVarP(&workspace, "workspace", "w", workspace, "Specify a workspace for ignore limits")
    _ = rootCmd.Flags().MarkHidden("allow-checks-to-panic")
}
