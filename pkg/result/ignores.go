package result

import (
	"fmt"
	"strings"
	"time"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"
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

		// ignore rule matches!
		return true
	}
	// no ignore rule found for this result
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
	IgnoreRuleID string
	Expiry       *time.Time
	Workspace    string
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
			annotation.IgnoreRuleID = val
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
