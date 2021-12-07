package result

import (
	"fmt"
	"strings"
	"time"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
	"github.com/zclconf/go-cty/cty"
)

func (res *Result) IsIgnored(workspace string) bool {
	for _, annotation := range res.Annotations() {
		// if there is an ignore code
		if annotation.IgnoreRuleID == "" || (annotation.IgnoreRuleID != res.RuleID && annotation.IgnoreRuleID != res.LegacyRuleID && annotation.IgnoreRuleID != "*") {
			continue
		}
		if annotation.Workspace != "" && annotation.Workspace != workspace {
			continue
		}
		if annotation.Expiry != nil && time.Now().After(*annotation.Expiry) {
			continue
		}
		if len(annotation.AllowedValues) > 0 {
			if checkAllowedValueIgnores(annotation, res) {
				return true
			}
		} else {
			// ignore rule matches!
			return true
		}

	}
	// no ignore rule found for this result
	return false
}

func checkAllowedValueIgnores(annotation Annotation, res *Result) bool {
	for _, allowedValue := range annotation.AllowedValues {
		parts := strings.Split(allowedValue, "=")
		if len(parts) != 2 {
			continue
		}
		attribute := parts[0]
		value := parts[1]

		for _, b := range res.Blocks() {
			if b.HasChild(attribute) {
				attr := b.GetAttribute(attribute)
				switch attr.Type() {
				case cty.Number:
					val64, _ := attr.Value().AsBigFloat().Float64()
					attrValueAsString := fmt.Sprintf("%d", int(val64))
					if attrValueAsString == value {
						return true
					}
				case cty.String:
					if attr.Value().AsString() == value {
						return true
					}
				}

			}
		}
	}
	return false
}

func (res *Result) Annotations() []Annotation {
	var annotations []Annotation
	for _, block := range res.Blocks() {
		_, comments, err := block.ReadLines()
		if err != nil {
			continue
		}
		for _, comment := range comments {
			annotations = append(annotations, findAnnotations(comment)...)
		}
		annotations = append(annotations, traverseModuleTreeForAnnotations(block)...)
	}

	if res.attribute != nil {
		_, comments, err := res.attribute.Range().ReadLines(true)
		if err == nil {
			for _, comment := range comments {
				annotations = append(annotations, findAnnotations(comment)...)
			}
		}
	}

	return annotations
}

func traverseModuleTreeForAnnotations(b block.Block) (annotations []Annotation) {

	if b.HasModuleBlock() {
		moduleBlock, err := b.GetModuleBlock()
		if err != nil {
			return
		}
		_, comments, err := moduleBlock.ReadLines()
		if err != nil {
			return
		}
		for _, comment := range comments {
			annotations = append(annotations, findAnnotations(comment)...)
		}

		annotations = append(annotations, traverseModuleTreeForAnnotations(moduleBlock)...)
	}

	return
}

type Annotation struct {
	IgnoreRuleID  string
	Expiry        *time.Time
	Workspace     string
	AllowedValues []string
}

func findAnnotations(input string) []Annotation {

	var annotations []Annotation

	bits := strings.Split(input, " ")
	for _, bit := range bits {
		bit := strings.TrimSpace(bit)
		bit = strings.TrimPrefix(bit, "#")
		bit = strings.TrimPrefix(bit, "//")
		bit = strings.TrimPrefix(bit, "/*")

		if strings.HasPrefix(bit, "tfsec:") {
			annotation, err := newAnnotation(bit)
			if err != nil {
				continue
			}
			annotations = append(annotations, annotation)
		}
	}

	return annotations
}

func newAnnotation(input string) (Annotation, error) {
	var annotation Annotation
	if !strings.HasPrefix(input, "tfsec:") {
		return annotation, fmt.Errorf("invalid annotation")
	}

	input = input[6:]

	segments := strings.Split(input, ":")

	for i := 0; i < len(segments)-1; i += 2 {
		key := segments[i]
		val := segments[i+1]
		switch key {
		case "ignore":
			extractAllowedValues(&annotation, val)
		case "exp":
			parsed, err := time.Parse("2006-01-02", val)
			if err != nil {
				return annotation, err
			}
			annotation.Expiry = &parsed
		case "ws":
			annotation.Workspace = val
		}
	}

	return annotation, nil
}

func extractAllowedValues(annotation *Annotation, val string) {
	if !strings.HasSuffix(val, "]") && !strings.Contains(val, "[") {
		annotation.IgnoreRuleID = val
		return
	}
	annotation.IgnoreRuleID = val[:strings.Index(val, "[")]
	annotation.AllowedValues = strings.Split(strings.Split(strings.TrimSuffix(val, "]"), "[")[1], ",")
}
