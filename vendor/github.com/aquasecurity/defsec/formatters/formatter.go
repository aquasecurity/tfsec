package formatters

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/aquasecurity/defsec/metrics"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
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
    GroupResults([]rules.Result) ([]GroupedResult, error)
}

type base struct {
    enableGrouping bool
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
        enableGrouping: true,
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

func key(result rules.Result) string {
    var severityInt int
    switch result.Severity() {
    case severity.Critical:
        severityInt = 1
    case severity.High:
        severityInt = 2
    case severity.Medium:
        severityInt = 3
    case severity.Low:
        severityInt = 4
    }
    return fmt.Sprintf("%d:%s:%s:%d", severityInt, result.Range(), result.Rule().AVDID, result.Status())
}

func (b *base) GroupResults(results []rules.Result) ([]GroupedResult, error) {

    // sort by key first
    sort.Slice(results, func(i, j int) bool {
        return key(results[i]) < key(results[j])
    })

    var output []GroupedResult
    var lastKey string
    var group GroupedResult
    for i, result := range results {
        currentKey := key(result)
        if !b.enableGrouping || lastKey != currentKey {
            if group.Len() > 0 {
                output = append(output, group)
            }
            group = GroupedResult{}
        }
        if err := group.Add(i+1, result); err != nil {
            return nil, err
        }
        lastKey = currentKey
    }
    if group.Len() > 0 {
        output = append(output, group)
    }

    return output, nil
}

type GroupedResult struct {
    start   int
    end     int
    results []rules.Result
}

func (g *GroupedResult) Add(i int, res rules.Result) error {
    if g.end > 0 {
        if i != g.end+1 {
            return fmt.Errorf("expecting result #%d, found #%d", g.end+1, i)
        }
    }
    if g.start == 0 {
        g.start = i
    }
    g.end = i
    g.results = append(g.results, res)
    return nil
}

func (g *GroupedResult) String() string {
    if g.start == g.end {
        return fmt.Sprintf("#%d", g.start)
    }
    return fmt.Sprintf("#%d-%d", g.start, g.end)
}

func (g *GroupedResult) Len() int {
    return len(g.results)
}

func (g *GroupedResult) Results() []rules.Result {
    return g.results
}
