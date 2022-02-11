package formatters

import (
    "fmt"
    "github.com/aquasecurity/defsec/rules"
    "github.com/aquasecurity/defsec/severity"
    "github.com/liamg/tml"
    "io"
    "os"
    "sort"
)

type Formatter interface {
    Output(results []rules.Result) error
}

type ConfigurableFormatter interface {
    Writer() io.Writer
    GetLinks(rules.Result) []string
    BaseDir() string
    DebugEnabled() bool
    GroupResults([]rules.Result) ([]GroupedResult, error)
}

type Base struct {
    enableGrouping bool
    enableMetrics  bool
    enableColours  bool
    enableDebug    bool
    baseDir        string
    writer         io.Writer
    outputOverride func(b ConfigurableFormatter, results []rules.Result) error
    linksOverride  func(result rules.Result) []string
}

func NewBase() *Base {
    return &Base{
        enableGrouping: true,
        enableMetrics:  true,
        enableColours:  true,
        enableDebug:    false,
        baseDir:        ".",
        writer:         os.Stdout,
        outputOverride: outputSARIF,
        linksOverride: func(result rules.Result) []string {
            return result.Rule().Links
        },
    }
}

func (b *Base) Writer() io.Writer {
    return b.writer
}

func (b *Base) DebugEnabled() bool {
    return b.enableDebug
}

func (b *Base) GetLinks(result rules.Result) []string {
    return b.linksOverride(result)
}

func (b *Base) BaseDir() string {
    return b.baseDir
}

func (b *Base) Output(results []rules.Result) error {
    if !b.enableColours {
        tml.DisableFormatting()
    }
    return b.outputOverride(b, results)
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

func (b *Base) GroupResults(results []rules.Result) ([]GroupedResult, error) {

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
