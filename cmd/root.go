package cmd

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/liamg/tfsec/scanner"
	"github.com/liamg/tfsec/version"
	"github.com/spf13/cobra"
)

var showVersion = false

func init() {
	rootCmd.Flags().BoolVarP(&showVersion, "version", "v", showVersion, "Show version information and exit")
}

var rootCmd = &cobra.Command{
	Use:   "tfsec [directory]",
	Short: "tfsec is a terraform security scanner",
	Long:  `tfsec is a simple tool to detect potential security vulnerabilities in your terraformed infrastructure.`,
	Run: func(cmd *cobra.Command, args []string) {

		if showVersion {
			fmt.Println(version.Version)
			os.Exit(0)
		}

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

		problems := 0

		err = filepath.Walk(dir,
			func(path string, info os.FileInfo, err error) error {
				if info.IsDir() || !strings.HasSuffix(path, ".tf") {
					return nil
				}

				if err != nil {
					return err
				}

				data, err := ioutil.ReadFile(path)
				if err != nil {
					return err
				}

				results, err := scanner.Scan(data)
				if err != nil {
					return err
				}

				lines := strings.Split(string(data), "\n")

				for _, result := range results {
					start := result.Line() - 2
					if start < 0 {
						start = 0
					}
					end := result.Line() + 2
					if end >= len(lines) {
						end = len(lines) - 1
					}
					code := ""
					for i := start; i < end; i++ {
						line := lines[i]
						if i == result.Line()-1 {
							line = fmt.Sprintf("\033[1m%s\033[0m", line)
						}
						code += fmt.Sprintf("% 6d | \033[0m %s\n", i+1, line)
					}

					rel := path
					if strings.HasPrefix(rel, dir) {
						rel = rel[len(dir)+1:]
					}

					fmt.Printf("[%s:%d] %s\n%s\n", rel, result.Line(), result.Description(), code)
					problems++
				}

				return nil
			})
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		if problems == 0 {
			fmt.Printf("\033[32m No problems detected.\033[0m\n")
		} else {
			fmt.Printf("\033[31m %d problem(s) detected. See above for details. If you wish to ignore a warning, add #tfsec:ignore to the line in question.\033[0m\n", problems)
			os.Exit(1)
		}

	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
