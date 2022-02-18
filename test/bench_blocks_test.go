package test

import (
	"testing"

	"github.com/aquasecurity/defsec/parsers/terraform"
	"github.com/aquasecurity/defsec/parsers/terraform/parser"
	"github.com/aquasecurity/tfsec/internal/pkg/testutil/filesystem"
)

func BenchmarkBlockParsing(b *testing.B) {

	fs, err := filesystem.New()
	if err != nil {
		panic(err)
	}
	defer func() { _ = fs.Close() }()

	createBadBlocks(fs)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p := parser.New(parser.OptionStopOnHCLError(true))
		if err := p.ParseDirectory(fs.RealPath("/project")); err != nil {
			panic(err)
		}
		modules, _, err := p.EvaluateAll()
		if err != nil {
			panic(err)
		}

		for _, m := range modules {
			terraform.NewModule(fs.RealPath("/project"), "", m.GetBlocks(), nil)
		}

	}

}
