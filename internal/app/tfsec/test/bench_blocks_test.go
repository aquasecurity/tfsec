package test

import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/parser"
	"github.com/aquasecurity/tfsec/internal/app/tfsec/testutil/filesystem"
)

func BenchmarkBlockParsing(b *testing.B) {

	fs, err := filesystem.New()
	if err != nil {
		panic(err)
	}
	defer fs.Close()

	createBadBlocks(fs)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		modules, err := parser.New(fs.RealPath("/project"), parser.OptionStopOnHCLError()).ParseDirectory()
		if err != nil {
			panic(err)
		}

		for _, m := range modules {
			block.NewHCLModule(fs.RealPath("/project"), "", m.GetBlocks(), nil)
		}

	}

}
