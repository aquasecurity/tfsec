package main

import (
	"fmt"
	"os"
	"path/filepath"

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

func init() {
	rootCmd.Flags().BoolVar(&disableColours, "no-colour", disableColours, "Disable coloured output")
	rootCmd.Flags().BoolVar(&disableColours, "no-color", disableColours, "Disable colored output (American style!)")
	rootCmd.Flags().BoolVarP(&showVersion, "version", "v", showVersion, "Show version information and exit")
	rootCmd.Flags().StringVarP(&format, "format", "f", format, "Select output format: default, json, csv, checkstyle, junit")
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
		if len(args) == 1 {
			dir, err = filepath.Abs(args[0])
		} else {
			dir, err = os.Getwd()
		}
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		formatter, err := getFormatter()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		blocks, err := parser.New().ParseDirectory(dir)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		results := scanner.New().Scan(blocks)
		if err := formatter(results); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		if len(results) == 0 {
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
