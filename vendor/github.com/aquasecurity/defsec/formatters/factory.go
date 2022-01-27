package formatters

import (
	"io"

	"github.com/aquasecurity/defsec/rules"
)

func New() *factory {
	return &factory{
		base: newBase(),
	}
}

type factory struct {
	base *base
}

func (f *factory) Build() Formatter {
	return f.base
}

func (f *factory) WithMetricsEnabled(enabled bool) *factory {
	f.base.enableMetrics = enabled
	return f
}

func (f *factory) WithDebugEnabled(enabled bool) *factory {
	f.base.enableDebug = enabled
	return f
}

func (f *factory) WithColoursEnabled(enabled bool) *factory {
	f.base.enableColours = enabled
	return f
}

func (f *factory) WithGroupingEnabled(enabled bool) *factory {
	f.base.enableGrouping = enabled
	return f
}

func (f *factory) WithBaseDir(dir string) *factory {
	f.base.baseDir = dir
	return f
}

func (f *factory) WithCustomFormatterFunc(fn func(configurableFormatter, []rules.Result) error) *factory {
	f.base.outputOverride = fn
	return f
}

func (f *factory) WithLinksFunc(fn func(result rules.Result) []string) *factory {
	f.base.linksOverride = fn
	return f
}

func (f *factory) WithWriter(w io.Writer) *factory {
	f.base.writer = w
	return f
}

func (f *factory) AsJSON() *factory {
	f.base.outputOverride = outputJSON
	return f
}

func (f *factory) AsCheckStyle() *factory {
	f.base.outputOverride = outputCheckStyle
	return f
}

func (f *factory) AsDefault() *factory {
	f.base.outputOverride = outputDefault
	return f
}

func (f *factory) AsCSV() *factory {
	f.base.outputOverride = outputCSV
	return f
}

func (f *factory) AsGIF() *factory {
	f.base.outputOverride = outputGif
	return f
}

func (f *factory) AsJUnit() *factory {
	f.base.outputOverride = outputJUnit
	return f
}

func (f *factory) AsSARIF() *factory {
	f.base.outputOverride = outputSARIF
	return f
}
