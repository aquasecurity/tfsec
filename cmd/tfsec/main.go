package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

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
	rootCmd.Flags().BoolVar(&debug.Enabled, "verbose", debug.Enabled, "Enable verbose logging")
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

		debug.Log("Loading custom checks...")
		if len(customCheckDir) == 0 {
			debug.Log("Using the default custom check folder")
			customCheckDir = fmt.Sprintf("%s/.tfsec", dir)
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
		blocks, err := parser.New(dir, tfvarsPath).ParseDirectory()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		debug.Log("Starting scanner...")
		results := scanner.New().Scan(blocks, excludedChecksList)
		if err := formatter(outputFile, results); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		if len(results) == 0 || softFail {
			os.Exit(0)
		}

		os.Exit(1)
	},
}

func getFormatter() (formatters.Formatter, error) {
	switch format {
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
