package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Masterminds/semver"
	debugging "github.com/aquasecurity/defsec/pkg/debug"
	"github.com/aquasecurity/defsec/pkg/extrafs"
	scanner "github.com/aquasecurity/defsec/pkg/scanners/terraform"
	"github.com/aquasecurity/defsec/pkg/scanners/terraform/executor"
	"github.com/aquasecurity/tfsec/internal/pkg/config"
	"github.com/aquasecurity/tfsec/version"
	"github.com/spf13/cobra"
)

type ExitCodeError struct {
	inner error
	code  int
}

func (e ExitCodeError) Error() string {
	if e.inner == nil {
		return ""
	}
	return e.inner.Error()
}

func (e ExitCodeError) Code() int {
	return e.code
}

var logger debugging.Logger

func Root() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:               "tfsec [directory]",
		Short:             "tfsec is a terraform security scanner",
		Long:              `tfsec is a simple tool to detect potential security vulnerabilities in your terraformed infrastructure.`,
		PersistentPreRunE: prerun,
		SilenceErrors:     true,
		Args:              cobra.RangeArgs(0, 1),
		RunE: func(cmd *cobra.Command, args []string) error {

			if debug {
				logger = debugging.New(cmd.ErrOrStderr(), "cmd")
				debugging.LogSystemInfo(cmd.ErrOrStderr(), version.Version)
			}

			logger.Log("Command args=%#v", args)

			// we handle our own errors, and usage does not need to be shown if we've got this far
			cmd.SilenceUsage = true

			dir, err := findDirectory(args)
			if err != nil {
				return err
			}

			logger.Log("Determined path dir=%s", dir)

			if len(tfvarsPaths) == 0 && unusedTfvarsPresent(dir) {
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "WARNING: A tfvars file was found but not automatically used. Did you mean to specify the --tfvars-file flag?\n")
			}

			root, rel, err := splitRoot(dir)
			if err != nil {
				return err
			}

			logger.Log("Determined path root=%s", root)
			logger.Log("Determined path rel=%s", rel)

			options, err := configureOptions(cmd, root, dir)
			if err != nil {
				return fmt.Errorf("invalid option: %w", err)
			}

			scnr := scanner.New(options...)
			results, metrics, err := scnr.ScanFSWithMetrics(context.TODO(), extrafs.OSDir(root), rel)
			if err != nil {
				return fmt.Errorf("scan failed: %w", err)
			}

			if printRegoInput {
				return nil
			}

			if runStatistics {
				statistics := executor.Statistics{}
				for _, result := range results {
					statistics = executor.AddStatisticsCount(statistics, result)
				}
				return statistics.PrintStatisticsTable(format, cmd.ErrOrStderr())
			}

			exitCode := getDetailedExitCode(metrics)
			logger.Log("Exit code based on results: %d", exitCode)

			formats := strings.Split(format, ",")
			if err := output(cmd, outputFlag, formats, root, rel, results, metrics); err != nil {
				return fmt.Errorf("failed to write output: %w", err)
			}

			if exitCode != 0 && !softFail {
				return &ExitCodeError{
					code: exitCode,
				}
			}

			return nil
		},
	}

	configureFlags(rootCmd)
	return rootCmd
}

func minVersionSatisfied(conf *config.Config) bool {

	if conf.MinimumRequiredVersion == "" {
		return true
	}

	minimum, err := semver.NewVersion(conf.MinimumRequiredVersion)
	if err != nil {
		return true
	}
	actual, err := semver.NewVersion(version.Version)
	if err != nil {
		return true
	}
	return minimum.Equal(actual) || minimum.LessThan(actual)
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

func splitRoot(dir string) (string, string, error) {
	root := "/"
	var rel string
	if vol := filepath.VolumeName(dir); vol != "" {
		root = vol
		if len(dir) <= len(vol)+1 {
			rel = "."
		} else {
			rel = dir[len(vol)+1:]
		}
	} else {
		var err error
		rel, err = filepath.Rel(root, dir)
		if err != nil {
			return "", "", fmt.Errorf("failed to set relative path: %w", err)
		}
	}
	return root, rel, nil
}

func findDirectory(args []string) (string, error) {
	var dir string
	workingDir, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("could not determine current directory: %w", err)
	}

	if len(args) > 1 {
		return "", fmt.Errorf("unexpected input - you must specify at most one directory to scan")
	}

	if len(args) == 1 {
		dir, err = filepath.Abs(filepath.Clean(args[0]))
		if err != nil {
			return "", fmt.Errorf("could not determine absolute path for provided path: %w", err)
		}
	} else {
		dir = workingDir
	}

	if dirInfo, err := os.Stat(dir); err != nil {
		return "", fmt.Errorf("failed to access provided path: %w", err)
	} else if !dirInfo.IsDir() {
		return "", fmt.Errorf("provided path is not a dir")
	}

	return dir, nil
}
