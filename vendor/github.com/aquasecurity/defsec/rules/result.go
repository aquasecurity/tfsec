package rules

import (
	"fmt"
	"strings"

	"github.com/aquasecurity/defsec/types"
)

type Status uint8

const (
	StatusFailed Status = iota
	StatusPassed
)

type Result struct {
	rule        Rule
	description string
	annotation  string
	status      Status
	metadata    *types.Metadata
}

func (r Result) Status() Status {
	return r.status
}

func (r Result) Rule() Rule {
	return r.rule
}

func (r Result) Description() string {
	return r.description
}

func (r Result) Annotation() string {
	return r.annotation
}

func (r Result) Metadata() *types.Metadata {
	return r.metadata
}

func (r Result) Reference() types.Reference {
	return r.metadata.Reference()
}

type Results []Result

func (r *Results) Add(description string, metadata *types.Metadata, annotation ...interface{}) {
	var annotationStr string
	if len(annotation) == 1 && metadata.IsExplicit() {
		annotationStr = rawToString(annotation[0])
	}
	*r = append(*r,
		Result{
			description: description,
			metadata:    metadata,
			annotation:  annotationStr,
		},
	)
}

func (r *Results) SetRule(rule Rule) {
	for i := range *r {
		(*r)[i].rule = rule
	}
}

func rawToString(raw interface{}) string {
	if raw == nil {
		return ""
	}
	switch t := raw.(type) {
	case int:
		return fmt.Sprintf("%d", t)
	case bool:
		return fmt.Sprintf("%t", t)
	case float64:
		return fmt.Sprintf("%f", t)
	case string:
		return fmt.Sprintf("%q", t)
	case []string:
		var items []string
		for _, item := range t {
			items = append(items, rawToString(item))
		}
		return fmt.Sprintf("[%s]", strings.Join(items, ", "))
	case []int:
		var items []string
		for _, item := range t {
			items = append(items, rawToString(item))
		}
		return fmt.Sprintf("[%s]", strings.Join(items, ", "))
	case []float64:
		var items []string
		for _, item := range t {
			items = append(items, rawToString(item))
		}
		return fmt.Sprintf("[%s]", strings.Join(items, ", "))
	case []bool:
		var items []string
		for _, item := range t {
			items = append(items, rawToString(item))
		}
		return fmt.Sprintf("[%s]", strings.Join(items, ", "))
	default:
		return "?"
	}
}
