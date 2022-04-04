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

func prerun(_ *cobra.Command, args []string) {

	// disable colour if running on windows - colour formatting doesn't work
	if disableColours || runtime.GOOS == "windows" {
		tml.DisableFormatting()
	}

	if showVersion {
		if version.Version == "" {
			fmt.Println("You are running a locally built version of tfsec.")
		} else {
			fmt.Println(version.Version)
		}
		os.Exit(0)
	}

	if runUpdate {
		updateVersion, err := updater.Update()
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "Error during update: %s\n", err.Error())
			os.Exit(1)
		}
		if updateVersion == "" {
			fmt.Println("You are already running the latest version.")
		} else {
			fmt.Printf("Successfully updated to %s.\n", updateVersion)
		}
		os.Exit(0)
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
			fmt.Fprintf(os.Stderr, "Directory was not provided, and tfsec encountered an error trying to determine the current working directory: %s\n", err)
			os.Exit(1)
		}

		stats, err := ignores.RunMigration(dir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Errors occurred while running migration: %s", err.Error())
			os.Exit(1)
		}
		if len(stats) > 0 {
			for _, stat := range stats {
				fmt.Printf("%s migrated from %s => %s\n", stat.Filename, stat.FromCode, stat.ToCode)
			}
		}
		os.Exit(0)
	}
}
