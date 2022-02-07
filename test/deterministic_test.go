package test

import (
	"testing"

	"github.com/aquasecurity/tfsec/internal/pkg/testutil/filesystem"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tfsec/internal/pkg/parser"
	"github.com/aquasecurity/tfsec/internal/pkg/scanner"
)

func Test_DeterministicResults(t *testing.T) {

	scanner.RegisterCheckRule(badRule)
	defer scanner.DeregisterCheckRule(badRule)

	fs, err := filesystem.New()
	require.NoError(t, err)
	defer fs.Close()
	require.NoError(t, fs.WriteTextFile("/project/first.tf", `
resource "problem" "uhoh" {
	bad = true
    for_each = other.thing
}
`))
	require.NoError(t, fs.WriteTextFile("/project/second.tf", `
resource "other" "thing" {
    for_each = local.list
}
`))
	require.NoError(t, fs.WriteTextFile("/project/third.tf", `
locals {
    list = {
        a = 1,
        b = 2,
    }
}
`))

	for i := 0; i < 100; i++ {
		blocks, err := parser.New(fs.RealPath("/project/"), parser.OptionStopOnHCLError()).ParseDirectory()
		require.NoError(t, err)
		results, _ := scanner.New().Scan(blocks)
		require.Len(t, results, 2)
	}
}
