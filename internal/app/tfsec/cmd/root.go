package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Masterminds/semver"
	"github.com/aquasecurity/defsec/pkg/extrafs"
	scanner "github.com/aquasecurity/defsec/pkg/scanners/terraform"
	"github.com/aquasecurity/defsec/pkg/scanners/terraform/executor"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/tfsec/internal/pkg/config"
	"github.com/aquasecurity/tfsec/internal/pkg/custom"
	"github.com/aquasecurity/tfsec/version"
	"github.com/spf13/cobra"
)

type ErrorWithExitCode struct {
	inner error
	code  int
}

func (e ErrorWithExitCode) Error() string {
	if e.inner == nil {
		return ""
	}
	return e.inner.Error()
}

func (e ErrorWithExitCode) Code() int {
	return e.code
}

func Root() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:               "tfsec [directory]",
		Short:             "tfsec is a terraform security scanner",
		Long:              `tfsec is a simple tool to detect potential security vulnerabilities in your terraformed infrastructure.`,
		PersistentPreRunE: prerun,
		SilenceErrors:     true,
		RunE: func(cmd *cobra.Command, args []string) error {

			// we handle our own errors, and usage does not need to be shown if we've got this far
			cmd.SilenceUsage = true

			var dir string
			var err error

			workingDir, err := os.Getwd()
			if err != nil {
				return fmt.Errorf("could not determine current directory: %s", err)
			}

			if len(args) == 1 {
				dir, err = filepath.Abs(args[0])
				if err != nil {
					return fmt.Errorf("could not determine absolute path for provided path: %s", err)
				}
			} else {
				dir = workingDir
			}

			if dirInfo, err := os.Stat(dir); err != nil {
				return fmt.Errorf("failed to access provided path: %s", err)
			} else if !dirInfo.IsDir() {
				return fmt.Errorf("provided path is not a dir")
			}

			if len(tfvarsPaths) == 0 && unusedTfvarsPresent(dir) {
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "WARNING: A tfvars file was found but not automatically used. Did you mean to specify the --tfvars-file flag?\n")
			}

			root, rel, err := splitRoot(dir)
			if err != nil {
				return err
			}

			options, err := configureOptions(cmd, root)
			if err != nil {
				return fmt.Errorf("invalid option: %s", err)
			}

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
						return fmt.Errorf("minimum tfsec version requirement not satisfied")
					}
					if conf.MinimumSeverity != "" {
						options = append(options, scanner.OptionWithMinimumSeverity(severity.StringToSeverity(conf.MinimumSeverity)))
					}
					options = append(options, scanner.OptionWithSeverityOverrides(conf.SeverityOverrides))
					options = append(options, scanner.OptionIncludeRules(conf.IncludedChecks))
					options = append(options, scanner.OptionExcludeRules(append(conf.ExcludedChecks, excludedRuleIDs)))
				}
			}

			if customCheckDir == "" {
				customCheckDir = filepath.Join(dir, ".tfsec")
			}
			if err := custom.Load(customCheckDir); err != nil {
				return fmt.Errorf("failed to load custom checks from %s: %w", customCheckDir, err)
			}

			osFS := extrafs.OSDir(root)

			scnr := scanner.New(options...)
			results, metrics, err := scnr.ScanFSWithMetrics(context.TODO(), osFS, rel)
			if err != nil {
				return fmt.Errorf("scan failed: %s", err)
			}

			if printRegoInput {
				return nil
			}

			if runStatistics {
				statistics := executor.Statistics{}
				for _, result := range results {
					statistics = executor.AddStatisticsCount(statistics, result)
				}
				statistics.PrintStatisticsTable(cmd.ErrOrStderr())
				return nil
			}

			formats := strings.Split(format, ",")
			if err := output(cmd, outputFlag, formats, rel, results, metrics); err != nil {
				return fmt.Errorf("failed to write output: %s", err)
			}

			// Soft fail always takes precedence. If set, only execution errors
			// produce a failure exit code (1).
			if softFail {
				return nil
			}

			exitCode := getDetailedExitCode(metrics)
			if exitCode != 0 {
				return &ErrorWithExitCode{
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
			return "", "", fmt.Errorf("failed to set relative path: %s", err)
		}
	}
	return root, rel, nil
}
