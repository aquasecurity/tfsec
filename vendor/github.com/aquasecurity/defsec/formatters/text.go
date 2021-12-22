package formatters

import (
	"io"

	"github.com/aquasecurity/defsec/rules"
)

func FormatText(writer io.Writer, results []rules.Result, baseDir string, options ...FormatterOption) error {
	return FormatDefault(writer, results, baseDir, append(options, NoColour, ConciseOutput)...)
}
