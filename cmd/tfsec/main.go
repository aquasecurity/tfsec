package main

import (
	"fmt"
	"os"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/cmd"
)

func main() {
	if err := cmd.Root().Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
