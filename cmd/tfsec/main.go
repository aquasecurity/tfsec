package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/cmd"
)

func main() {
	if err := cmd.Root().Execute(); err != nil {
		if err.Error() != "" {
			fmt.Printf("Error: %s\n", err)
		}
		var exitErr *cmd.ExitCodeError
		if errors.As(err, &exitErr) {
			os.Exit(exitErr.Code())
		}
		os.Exit(1)
	}
}
