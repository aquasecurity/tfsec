package examples

import (
	"fmt"
	"strings"
)

type machine struct {
	stack           []string
	inPath          bool
	found           bool
	output          []string
	tabStr          string
	tabChecked      bool
	multilineMarker string
	dotPath         string
	value           interface{}
	renameResource  string
}

func (m *machine) calcTabs(line string) {
	if !m.tabChecked && strings.TrimPrefix(line, " ") != line {
		var size int
		for _, c := range line {
			if c == ' ' {
				size++
				continue
			}
			break
		}
		m.tabChecked = true
		m.tabStr = strings.Repeat(" ", size)
	}
}

func (m *machine) processAttributeLine(line string) string {
	parts := strings.Split(line, "=")
	name := strings.TrimSpace(parts[0])
	if strings.Join(append(m.stack, name), ".") == m.dotPath {
		line = fmt.Sprintf("%s= %s", parts[0], sprintHCL(m.value))
		if m.value == nil {
			line = ""
		}
		m.found = true
	}
	if strings.Contains(line, "<<") {
		m.multilineMarker = strings.Split(line, "<<")[1]
	}
	if strings.HasSuffix(line, "{") {
		m.stack = append(m.stack, name)
	}
	return line
}

func (m *machine) processBlockOpening(line string) string {
	if m.renameResource != "" && len(strings.Split(m.dotPath, ".")) >= 3 {
		if dotSegmentFromLine(line) == strings.Join(strings.Split(m.dotPath, ".")[:3], ".") {
			parts := strings.Split(strings.TrimSpace(line), " ")
			line = fmt.Sprintf("%s %s \"%s\" {", parts[0], parts[1], m.renameResource)
		}
	}
	m.stack = append(m.stack, dotSegmentFromLine(line))
	return line
}

func (m *machine) processBlockClosing(line string) string {
	if m.inPath && !m.found && m.value != nil {
		// we were in the right place - did we find our attr? if not, we need to add it
		inject := expandPathAndValue(strings.TrimPrefix(m.dotPath, strings.Join(m.stack, ".")+"."), m.value, m.tabStr, len(m.stack))
		m.output = append(m.output, inject)
		m.found = true
	}

	m.stack = m.stack[:len(m.stack)-1]
	return line
}

func (m *machine) processLine(line string) {

	if m.multilineMarker != "" {
		if line == m.multilineMarker {
			m.multilineMarker = ""
		}
		m.output = append(m.output, line)
		return
	}

	m.calcTabs(line)

	if strings.Contains(line, "=") {
		// handle attribute definition
		line = m.processAttributeLine(line)
	} else if strings.HasSuffix(strings.TrimSpace(line), "{") {
		line = m.processBlockOpening(line)
	} else if strings.HasSuffix(strings.TrimSpace(line), "}") {
		line = m.processBlockClosing(line)
	}

	m.inPath = strings.HasPrefix(m.dotPath, strings.Join(m.stack, "."))
	m.output = append(m.output, line)
}

/*
 SetAttribute sets a given attribute value from a dot separated hcl path. resource paths should be prefixed with "resource."
	This assumes a certain standard of clean Terraform code as is available in the provider examples.
	It's used for building rule example code and thus only builds an approximation of what is needed, to be manually tweaked afterwards.
*/
func SetAttribute(rawHCL string, dotPath string, value interface{}, renameResource string) string {

	m := machine{
		tabStr:         "\t",
		dotPath:        dotPath,
		value:          value,
		renameResource: renameResource,
	}

	for _, line := range strings.Split(rawHCL, "\n") {
		m.processLine(line)
	}

	return strings.Join(m.output, "\n")
}

func expandPathAndValue(dotPath string, value interface{}, tabStr string, tabSize int) string {
	tab := strings.Repeat(tabStr, tabSize)
	segments := strings.Split(dotPath, ".")
	if len(segments) == 1 {
		return fmt.Sprintf("%s%s = %s", tab, segments[0], sprintHCL(value))
	}

	return fmt.Sprintf("%s%s {\n%s\n%s}", tab, segments[0], expandPathAndValue(strings.Join(segments[1:], "."), value, tabStr, tabSize+1), tab)
}

func dotSegmentFromLine(line string) string {
	parts := strings.Split(strings.Split(strings.TrimSpace(line), "{")[0], " ")
	var output []string
	for i, part := range parts {
		if i == 2 {
			part = "*"
		}
		part = strings.ReplaceAll(part, `"`, "")
		if part == "" {
			continue
		}
		output = append(output, part)
	}
	return strings.Join(output, ".")
}

func sprintHCL(value interface{}) string {
	if s, ok := value.(string); ok {
		return fmt.Sprintf("%q", s)
	}
	if s, ok := value.([]string); ok {
		if len(s) == 0 {
			return `[]`
		}
		return fmt.Sprintf(`["%s"]`, strings.Join(s, `", "`))
	}
	return fmt.Sprintf("%v", value)
}
