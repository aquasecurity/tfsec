package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/liamg/tfsec/internal/app/tfsec/formatters"

	"github.com/liamg/tml"

	_ "github.com/liamg/tfsec/internal/app/tfsec/checks"
	"github.com/liamg/tfsec/internal/app/tfsec/parser"
	"github.com/liamg/tfsec/internal/app/tfsec/scanner"
	"github.com/liamg/tfsec/version"
	"github.com/spf13/cobra"
)

var showVersion = false
var disableColours = false
var format string
var softFail = false
var excludedChecks string
var excludeDirectories []string
var tfvarsPath string

func init() {
	rootCmd.Flags().BoolVar(&disableColours, "no-colour", disableColours, "Disable coloured output")
	rootCmd.Flags().BoolVar(&disableColours, "no-color", disableColours, "Disable colored output (American style!)")
	rootCmd.Flags().BoolVarP(&showVersion, "version", "v", showVersion, "Show version information and exit")
	rootCmd.Flags().StringVarP(&format, "format", "f", format, "Select output format: default, json, csv, checkstyle, junit")
	rootCmd.Flags().StringVarP(&excludedChecks, "exclude", "e", excludedChecks, "Provide checks via , without space to exclude from run.")
	rootCmd.Flags().BoolVarP(&softFail, "soft-fail", "s", softFail, "Runs checks but suppresses error code")
	rootCmd.Flags().StringSliceVar(&excludeDirectories, "exclude-dir", []string{}, "Exclude a directory from the scan. You can use this flag multiple times to exclude further directories.")
	rootCmd.Flags().StringVar(&tfvarsPath, "tfvars-file", tfvarsPath, "Path to .tfvars file")
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

		if disableColours {
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

		if len(args) == 1 {
			dir, err = filepath.Abs(args[0])
		} else {
			dir, err = os.Getwd()
		}
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		if len(excludedChecks) > 0 {
			excludedChecksList = strings.Split(excludedChecks, ",")
		}

		formatter, err := getFormatter()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		var absoluteExcludes []string
		for _, exclude := range excludeDirectories {
			exDir, err := filepath.Abs(exclude)
			if err != nil {
				continue
			}
			absoluteExcludes = append(absoluteExcludes, exDir)
		}

		if tfvarsPath != "" {
			tfvarsPath, err = filepath.Abs(tfvarsPath)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
		}

		blocks, err := parser.New().ParseDirectory(dir, absoluteExcludes, tfvarsPath)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		results := scanner.New().Scan(blocks, excludedChecksList)
		if err := formatter(results); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		if len(results) == 0 || softFail {
			os.Exit(0)
		}

		os.Exit(1)
	},
}

func getFormatter() (func([]scanner.Result) error, error) {
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
	default:
		return nil, fmt.Errorf("invalid format specified: '%s'", format)
	}
}
