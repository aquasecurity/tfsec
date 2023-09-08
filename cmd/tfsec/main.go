package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/cmd"
)

const transitionMsg = `
======================================================
tfsec is joining the Trivy family

tfsec will continue to remain available 
for the time being, although our engineering 
attention will be directed at Trivy going forward.

You can read more here: 
https://github.com/aquasecurity/tfsec/discussions/1994
======================================================
`

func main() {
	fmt.Fprint(os.Stderr, transitionMsg)
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
