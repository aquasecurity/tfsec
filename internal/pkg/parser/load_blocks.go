package parser

import (
	"fmt"
	"strings"
	"time"

	"github.com/aquasecurity/defsec/metrics"
	"github.com/aquasecurity/defsec/types"
	"github.com/aquasecurity/tfsec/internal/pkg/block"
	"github.com/aquasecurity/tfsec/internal/pkg/schema"
	"github.com/hashicorp/hcl/v2"
)

func LoadBlocksFromFile(file File) (hcl.Blocks, []block.Ignore, error) {

	var ignores []block.Ignore
	for _, ignore := range parseIgnores(file.file.Bytes) {
		ignore.Range = types.NewRange(file.path, ignore.Range.GetStartLine(), ignore.Range.GetEndLine())

		fmt.Println(ignore.Range)
		ignores = append(ignores, ignore)
	}

	t := metrics.Timer("timings", "hcl parsing")
	t.Start()
	defer t.Stop()

	contents, diagnostics := file.file.Body.Content(schema.TerraformSchema_0_12)
	if diagnostics != nil && diagnostics.HasErrors() {
		return nil, nil, diagnostics
	}

	if contents == nil {
		return nil, nil, fmt.Errorf("file contents is empty")
	}

	return contents.Blocks, ignores, nil
}

func parseIgnores(data []byte) []block.Ignore {
	var ignores []block.Ignore
	for i, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		lineIgnores := parseIgnoresFromLine(line)
		for _, lineIgnore := range lineIgnores {
			lineIgnore.Range = types.NewRange("", i+1, i+1)
			ignores = append(ignores, lineIgnore)
		}
	}
	for a, ignoreA := range ignores {
		if ignoreA.Block {
			continue
		}
		for _, ignoreB := range ignores {
			if ignoreB.Block {
				continue
			}
			if ignoreA.Range.GetStartLine()+1 == ignoreB.Range.GetStartLine() {
				ignoreA.Range = ignoreB.Range
				ignores[a] = ignoreA
			}
		}
	}
	return ignores

}

func parseIgnoresFromLine(input string) []block.Ignore {

	var ignores []block.Ignore

	bits := strings.Split(strings.TrimSpace(input), " ")
	for i, bit := range bits {
		bit := strings.TrimSpace(bit)
		bit = strings.TrimPrefix(bit, "#")
		bit = strings.TrimPrefix(bit, "//")
		bit = strings.TrimPrefix(bit, "/*")

		if strings.HasPrefix(bit, "tfsec:") {
			ignore, err := parseIgnoreFromComment(bit)
			if err != nil {
				continue
			}
			ignore.Block = i == 0
			ignores = append(ignores, *ignore)
		}
	}

	return ignores
}

func parseIgnoreFromComment(input string) (*block.Ignore, error) {
	var ignore block.Ignore
	if !strings.HasPrefix(input, "tfsec:") {
		return nil, fmt.Errorf("invalid ignore")
	}

	input = input[6:]

	segments := strings.Split(input, ":")

	for i := 0; i < len(segments)-1; i += 2 {
		key := segments[i]
		val := segments[i+1]
		switch key {
		case "ignore":
			ignore.RuleID = val
		case "exp":
			parsed, err := time.Parse("2006-01-02", val)
			if err != nil {
				return &ignore, err
			}
			ignore.Expiry = &parsed
		case "ws":
			ignore.Workspace = val
		}
	}

	return &ignore, nil
}
