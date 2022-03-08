package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/aquasecurity/tfsec/pkg/scanner"

	"github.com/aquasecurity/tfsec/internal/pkg/executor"
	_ "github.com/aquasecurity/tfsec/internal/pkg/rules"
	"github.com/spf13/cobra"
)

func Root() *cobra.Command {
	return rootCmd
}

var rootCmd = &cobra.Command{
	Use:              "tfsec [directory]",
	Short:            "tfsec is a terraform security scanner",
	Long:             `tfsec is a simple tool to detect potential security vulnerabilities in your terraformed infrastructure.`,
	PersistentPreRun: prerun,
	RunE: func(_ *cobra.Command, args []string) error {

		var dir string
		var err error

		if len(args) == 1 {
			dir, err = filepath.Abs(args[0])
			if err != nil {
				failf("Error determining absolute path for provided path: %s", err)
			}
		} else {
			dir, err = os.Getwd()
			if err != nil {
				failf("Error determining current directory: %s", err)
			}
		}

		if dirInfo, err := os.Stat(dir); err != nil {
			failf("Error accessing provided path: %s", err)
		} else if !dirInfo.IsDir() {
			failf("The provided path is not a dir, exiting")
		}

		if len(tfvarsPaths) == 0 && unusedTfvarsPresent(dir) {
			_, _ = fmt.Fprintf(os.Stderr, "WARNING: A tfvars file was found but not automatically used. Did you mean to specify the --tfvars-file flag?\n")
		}

		options, err := configureOptions(dir)
		if err != nil {
			failf("invalid option: %s", err)
		}
		scnr := scanner.New(options...)
		if err := scnr.AddPath(dir); err != nil {
			failf("Parse error: %s", err)
		}
		results, metrics, err := scnr.Scan()
		if err != nil {
			failf("Scan error: %s", err)
		}

		if runStatistics {
			statistics := executor.Statistics{}
			for _, result := range results {
				statistics = executor.AddStatisticsCount(statistics, result)
			}
			statistics.PrintStatisticsTable()
			return nil
		}

		formats := strings.Split(format, ",")
		if err := output(outputFlag, formats, dir, results, metrics); err != nil {
			failf("Failed to write output: %s", err)
		}

		// Soft fail always takes precedence. If set, only execution errors
		// produce a failure exit code (1).
		if softFail {
			return nil
		}

		os.Exit(getDetailedExitCode(metrics))
		return nil
	},
}

func failf(format string, a ...interface{}) {
	_, _ = fmt.Fprintf(os.Stderr, format+"\n", a...)
	os.Exit(1)
}

func getDetailedExitCode(metrics scanner.Metrics) int {
	// If there are no failed rules, then produce a success exit code (0).
	if metrics.Executor.Counts.Failed == 0 {
		return 0
	}

	// If there are some failed rules but they are all LOW severity, then
	// produce a special failure exit code (2).
	if metrics.Executor.Counts.Failed == metrics.Executor.Counts.Low {
		return 2
	}

	// If there is any failed check of CRITICAL, HIGH, MEDIUM severity, then
	// produce the regular failure exit code (1).
	return 1
}

func unusedTfvarsPresent(checkDir string) bool {
	glob := fmt.Sprintf("%s/*.tfvars", checkDir)
	if matches, err := filepath.Glob(glob); err == nil && len(matches) > 0 {
		return true
	}
	return false
}
