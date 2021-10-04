package test

import (
	"fmt"
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/parser"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/scanner"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil"
)

func BenchmarkCalculate(b *testing.B) {

	fs, err := testutil.NewFilesystem()
	if err != nil {
		panic(err)
	}
	defer fs.Close()

	_ = fs.WriteTextFile("/project/main.tf", `
		module "something" {
			source = "../modules/problem"
		}
		`)

	for _, rule := range scanner.GetRegisteredRules() {
		_ = fs.WriteTextFile(fmt.Sprintf("/modules/problem/%s.tf", rule.ID()), rule.Documentation.BadExample[0])
	}

	for i := 0; i < b.N; i++ {
		blocks, err := parser.New(fs.RealPath("/project"), parser.OptionStopOnHCLError()).ParseDirectory()
		if err != nil {
			panic(err)
		}
		_ = scanner.New().Scan(blocks)
	}
}
