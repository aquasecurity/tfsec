package main

import (
	"fmt"

	"github.com/tfsec/tfsec/pkg/externalscan"
)

func main() {
	
	scanner := externalscan.NewExternalScanner()

	_ = scanner.AddFile("../custom/custom_check.tf")
	_ = scanner.AddFile("../custom/modules/public_custom_bucket/main.tf")
	_ = scanner.AddFile("../good/good.tf")
	_ = scanner.AddFile("../withVars/main.tf")
	_ = scanner.AddFile("../withVars/variables.tf")

	results, err := scanner.Scan()
	if err != nil {
		panic(err)
	}

	for _, result := range results {
		fmt.Printf("%s: %s\n", result.RuleID, result.Description)
	}
}
