package main

import (
	"fmt"

	"github.com/aquasecurity/tfsec/pkg/externalscan"
)

func main() {
	scanner := externalscan.NewExternalScanner(externalscan.OptionIncludePassed())

	_ = scanner.AddPath("../custom/custom_check.tf")
	_ = scanner.AddPath("../custom/modules/public_custom_bucket/main.tf")
	_ = scanner.AddPath("../good/good.tf")
	_ = scanner.AddPath("../withVars/main.tf")
	_ = scanner.AddPath("../withVars/variables.tf")

	results, _ := scanner.Scan()
	for _, result := range results {
		fmt.Printf("%s: %#v\n", result.RuleID, result)
	}
}
