package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/aquasecurity/tfsec/internal/pkg/ignores"
	"github.com/aquasecurity/tfsec/internal/pkg/updater"
	"github.com/aquasecurity/tfsec/version"
	"github.com/liamg/tml"
	"github.com/spf13/cobra"
)

func prerun(cmd *cobra.Command, args []string) error {

	cmd.SilenceUsage = true

	// disable colour if running on windows - colour formatting doesn't work
	if disableColours || (runtime.GOOS == "windows" && os.Getenv("TERM") == "") {
		tml.DisableFormatting()
		disableColours = true // set this to prevent syntax highlighting later
	} else {
		tml.EnableFormatting()
	}

	if showVersion {
		if version.Version == "" {
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), "You are running a locally built version of tfsec.")
		} else {
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), version.Version)
		}
		return &ExitCodeError{code: 0}
	}

	if runUpdate {
		updateVersion, err := updater.Update()
		if err != nil {
			return fmt.Errorf("update failed: %w", err)
		}
		if updateVersion == "" {
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), "You are already running the latest version.")
		} else {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Successfully updated to %s.\n", updateVersion)
		}
		return &ExitCodeError{code: 0}
	}

	if migrateIgnores {
		var dir string
		var err error

		if len(args) == 1 {
			dir, err = filepath.Abs(args[0])
		} else {
			dir, err = os.Getwd()
		}
		if err != nil {
			return fmt.Errorf("directory was not provided, and tfsec encountered an error trying to determine the current working directory: %w", err)
		}

		stats, err := ignores.RunMigration(dir)
		if err != nil {
			return fmt.Errorf("migration failed: %w", err)
		}
		if len(stats) > 0 {
			for _, stat := range stats {
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s migrated from %s => %s\n", stat.Filename, stat.FromCode, stat.ToCode)
			}
		}
		return &ExitCodeError{code: 0}
	}

	return nil
}
