package formatters

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/aquasecurity/defsec/metrics"
	"github.com/aquasecurity/defsec/rules"
	"github.com/liamg/tml"
)

type Formatter interface {
	Output(results []rules.Result) error
}

type configurableFormatter interface {
	Writer() io.Writer
	GetLinks(rules.Result) []string
	PrintMetrics()
	BaseDir() string
	DebugEnabled() bool
}

type base struct {
	enableMetrics  bool
	enableColours  bool
	enableDebug    bool
	baseDir        string
	writer         io.Writer
	outputOverride func(b configurableFormatter, results []rules.Result) error
	linksOverride  func(result rules.Result) []string
}

func newBase() *base {
	return &base{
		enableMetrics:  true,
		enableColours:  true,
		enableDebug:    false,
		baseDir:        ".",
		writer:         os.Stdout,
		outputOverride: outputDefault,
		linksOverride: func(result rules.Result) []string {
			return result.Rule().Links
		},
	}
}

func (b *base) Writer() io.Writer {
	return b.writer
}

func (b *base) DebugEnabled() bool {
	return b.enableDebug
}

func (b *base) GetLinks(result rules.Result) []string {
	return b.linksOverride(result)
}

func (b *base) BaseDir() string {
	return b.baseDir
}

func (b *base) Output(results []rules.Result) error {
	if !b.enableColours {
		tml.DisableFormatting()
	}
	return b.outputOverride(b, results)
}

func (b *base) PrintMetrics() {

	if !b.enableMetrics {
		return
	}

	categories := metrics.General()

	if b.enableDebug {
		categories = append(categories, metrics.Debug()...)
	}

	for _, category := range categories {
		tml.Fprintf(b.Writer(), "  <bold>%s</bold>\n  %s\n", category.Name(), strings.Repeat("─", 42))
		for _, metric := range category.Metrics() {
			if metric.Name() != "total" {
				_ = tml.Fprintf(b.Writer(), "  <dim>%-20s</dim> %s\n", metric.Name(), metric.Value())
			}
		}
		for _, metric := range category.Metrics() {
			if metric.Name() == "total" {
				_ = tml.Fprintf(b.Writer(), "  <dim>%-20s</dim> %s\n", metric.Name(), metric.Value())
			}
		}
		fmt.Fprintf(b.Writer(), "\n")
	}

}
